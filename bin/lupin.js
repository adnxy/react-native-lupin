#!/usr/bin/env node
/**
 * lupin.js — Static bundle security scanner for Expo/React Native
 * ---------------------------------------------------------------
 * Scans compiled JS bundles for risky patterns: hard-coded secrets,
 * eval, insecure http URLs, and more.
 *
 * Usage:
 *   # Auto-detect project and find bundles
 *   lupin
 *
 *   # Specify project type
 *   lupin --type expo
 *   lupin --type rn-cli
 *
 *   # Scan all found bundles without prompting
 *   lupin --scan-all
 *
 *   # Manual mode - specify bundle directly
 *   lupin --bundle path/to/main.jsbundle
 *   lupin -b ./dist/_expo/static/js/ios/entry-*.js
 *
 *   # With JSON report and custom fail level
 *   lupin --json report.json --fail-level high
 *
 * Exit codes:
 *   0 = no findings at/above fail level
 *   1 = findings at/above fail level
 */

import fs from 'fs';
import path from 'path';
import { program } from 'commander';
import { glob } from 'glob';
import { Buffer } from 'buffer';

import { CORE_RULES } from './rules/core-rules.js';
import { DEPENDENCY_RULES } from './rules/dependency-security.js';
import { FILE_STORAGE_RULES } from './rules/file-storage-security.js';
import { PERMISSIONS_PRIVACY_RULES } from './rules/permissions-privacy.js';
import { OBFUSCATION_BUILD_RULES } from './rules/obfuscation-build.js';
import { AUTH_SESSION_RULES } from './rules/auth-session.js';
import { REACT_NATIVE_RULES } from './rules/react-native-specific.js';

let chalk;
try {
  chalk = (await import('chalk')).default;
} catch {
  chalk = new Proxy({}, { get: () => (x) => x }); // noop if chalk missing
}

/** ---------- Utilities ---------- */

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function severityGte(a, b) {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

function loadBundle(filepath) {
  if (!fs.existsSync(filepath)) {
    throw new Error(`Bundle not found: ${filepath}`);
  }
  return fs.readFileSync(filepath, 'utf8');
}

function readJsonSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

/** ---------- Combine all rules ---------- */
const RULES = [
  ...CORE_RULES,
  ...DEPENDENCY_RULES,
  ...FILE_STORAGE_RULES,
  ...PERMISSIONS_PRIVACY_RULES,
  ...OBFUSCATION_BUILD_RULES,
  ...AUTH_SESSION_RULES,
  ...REACT_NATIVE_RULES,
];

/** ---------- Core scanning helpers (minimal - kept for formatter) ---------- */

function slicePreview(s, max = 100) {
  if (s.length <= max) return s;
  return s.slice(0, Math.floor(max / 2)) + '…' + s.slice(s.length - Math.floor(max / 2));
}

/** ---------- Formatter ---------- */

function formatTable(findings) {
  const lines = [];
  const cols = ['ID', 'Severity', 'Title', 'Message/Match', 'Pos'];
  const widths = [10, 9, 26, 56, 8];

  function pad(str = '', w) {
    const s = (str + '').replace(/\s+/g, ' ');
    return s.length > w ? s.slice(0, w - 1) + '…' : s.padEnd(w);
  }

  lines.push(
    chalk.bold(
      [pad(cols[0], widths[0]), pad(cols[1], widths[1]), pad(cols[2], widths[2]), pad(cols[3], widths[3]), pad(cols[4], widths[4])].join(
        '  '
      )
    )
  );

  for (const f of findings) {
    const sevColor =
      f.severity === 'critical'
        ? chalk.bold.magenta
        : f.severity === 'high'
        ? chalk.red
        : f.severity === 'medium'
        ? chalk.yellow
        : f.severity === 'low'
        ? chalk.blue
        : chalk.gray;

    lines.push(
      [
        pad(f.id, widths[0]),
        pad(sevColor(f.severity.toUpperCase()), widths[1]),
        pad(f.title, widths[2]),
        pad(f.match ? `${f.message} (${slicePreview(f.match, 48)})` : f.message, widths[3]),
        pad(String(f.position ?? '-'), widths[4]),
      ].join('  ')
    );
  }
  return lines.join('\n');
}

/** ---------- Project type detection & bundle discovery ---------- */

function detectProjectType(baseDir = process.cwd()) {
  // Check for Expo
  const appJsonPath = path.join(baseDir, 'app.json');
  if (fs.existsSync(appJsonPath)) {
    try {
      const appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
      if (appJson.expo) return 'expo';
    } catch {}
  }

  // Check for RN CLI
  const hasAndroid = fs.existsSync(path.join(baseDir, 'android'));
  const hasIos = fs.existsSync(path.join(baseDir, 'ios'));
  const packageJsonPath = path.join(baseDir, 'package.json');
  
  if ((hasAndroid || hasIos) && fs.existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      if (pkg.dependencies?.['react-native'] || pkg.devDependencies?.['react-native']) {
        return 'rn-cli';
      }
    } catch {}
  }

  return null;
}

async function findBundles(projectType, baseDir = process.cwd()) {
  const bundles = [];

  if (projectType === 'expo') {
    // Expo bundles are in dist/_expo/static/js/{platform}/
    const patterns = [
      'dist/_expo/static/js/**/*.js',
      '.expo/static/js/**/*.js',
      'web-build/static/js/**/*.js'
    ];
    
    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => 
          // Exclude tiny files, likely not main bundles
          fs.statSync(f).size > 10000
        ));
      } catch {}
    }
  } else if (projectType === 'rn-cli') {
    // React Native CLI bundles
    const patterns = [
      'android/app/build/generated/assets/react/**/index.android.bundle',
      'android/app/src/main/assets/index.android.bundle',
      'ios/build/**/main.jsbundle',
      'ios/main.jsbundle',
      '*.bundle' // fallback
    ];

    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => 
          fs.statSync(f).size > 10000
        ));
      } catch {}
    }
  }

  // Remove duplicates
  return [...new Set(bundles)];
}

function promptUser(question) {
  return new Promise((resolve) => {
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });
    readline.question(question, (answer) => {
      readline.close();
      resolve(answer.trim());
    });
  });
}

/** ---------- CLI ---------- */

program
  .option('-b, --bundle <path>', 'Path to compiled JS bundle (manual mode)')
  .option('-t, --type <type>', 'Project type: expo or rn-cli (auto-detects if not specified)')
  .option('-s, --sourcemap <path>', 'Optional path to source map (for future mapping enhancements)')
  .option('--json [outfile]', 'Write JSON report (default: lupin-report-{timestamp}.json). Enabled by default.')
  .option('--no-json', 'Disable automatic JSON report generation')
  .option('--fail-level <level>', 'Exit non-zero if any finding >= level (info|low|medium|high|critical)', 'medium')
  .option('--show-level <level>', 'Only display findings >= level on screen (info|low|medium|high|critical). JSON contains all.', 'medium')
  .option('--max-findings <n>', 'Limit number of findings (for noisy bundles)', (v) => parseInt(v, 10), 5000)
  .option('--scan-all', 'Scan all found bundles without prompting')
  .option('--no-color', 'Disable colored output')
  .parse(process.argv);

const opts = program.opts();

// Auto-generate JSON report filename if enabled and no filename provided
if (opts.json !== false) {
  if (opts.json === true || opts.json === undefined) {
    // Generate default filename with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    opts.json = `lupin-report-${timestamp}.json`;
  }
}

(async function main() {
  try {
    let bundlesToScan = [];

    // Manual mode: user specified a bundle
    if (opts.bundle) {
      bundlesToScan = [path.resolve(opts.bundle)];
    } else {
      // Auto-discovery mode
      console.log(`
${chalk.bold.cyan('╔═══════════════════════════════════════════════════════════════════════════════╗')}
${chalk.bold.cyan('║')}${' '.repeat(79)}${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}          ${chalk.bold.magenta('🔒 LUPIN')} ${chalk.bold.white('━')} ${chalk.bold.cyan('Bundle Security Scanner')}                     ${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}          ${chalk.gray('React Native & Expo Security Auditor')}                      ${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}${' '.repeat(79)}${chalk.bold.cyan('║')}
${chalk.bold.cyan('╚═══════════════════════════════════════════════════════════════════════════════╝')}
`);

      // Detect or use specified project type
      let projectType = opts.type?.toLowerCase();
      if (!projectType) {
        projectType = detectProjectType();
        if (projectType) {
          console.log(chalk.cyan(`✓ Detected project type: ${projectType}`));
        } else {
          console.log(chalk.yellow('⚠ Could not auto-detect project type.'));
          const answer = await promptUser('Enter project type (expo/rn-cli): ');
          projectType = answer.toLowerCase();
          if (!['expo', 'rn-cli'].includes(projectType)) {
            throw new Error('Invalid project type. Use "expo" or "rn-cli"');
          }
        }
      } else {
        console.log(chalk.cyan(`✓ Using specified project type: ${projectType}`));
      }

      // Find bundles
      console.log(chalk.gray('Searching for bundle files...'));
      const foundBundles = await findBundles(projectType);

      if (foundBundles.length === 0) {
        console.log(chalk.red('\n✗ No bundle files found.'));
        console.log(chalk.gray('\nTips:'));
        console.log(chalk.gray('  - For Expo: run "npx expo export" first'));
        console.log(chalk.gray('  - For RN CLI: build your app first'));
        console.log(chalk.gray('  - Or use: --bundle <path> to specify manually'));
        process.exit(1);
      }

      console.log(chalk.green(`  ✨ Found ${chalk.bold.white(foundBundles.length)} bundle file(s)\n`));
      console.log(chalk.gray(`  ╭${'─'.repeat(76)}╮`));
      foundBundles.forEach((b, i) => {
        const size = Math.round(fs.statSync(b).size / 1024);
        const relativePath = path.relative(process.cwd(), b);
        const displayPath = relativePath.length > 60 ? '...' + relativePath.slice(-57) : relativePath;
        const sizeStr = `${size.toLocaleString()} KB`;
        const numberColor = i === 0 ? chalk.cyan : chalk.gray;
        console.log(chalk.gray(`  │ `) + numberColor(`${i + 1}. `) + chalk.white(displayPath.padEnd(62)) + chalk.cyan(sizeStr.padStart(8)) + chalk.gray(` │`));
      });
      console.log(chalk.gray(`  ╰${'─'.repeat(76)}╯`));

      // Determine which bundles to scan
      if (opts.scanAll || foundBundles.length === 1) {
        bundlesToScan = foundBundles;
      } else {
        const answer = await promptUser('\nScan all bundles? (y/n) or enter number to scan specific: ');
        if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
          bundlesToScan = foundBundles;
        } else if (answer.match(/^\d+$/)) {
          const idx = parseInt(answer, 10) - 1;
          if (idx >= 0 && idx < foundBundles.length) {
            bundlesToScan = [foundBundles[idx]];
          } else {
            throw new Error('Invalid bundle number');
          }
        } else {
          bundlesToScan = [foundBundles[0]]; // default to first
        }
      }
      console.log('');
    }

    // Scan each bundle
    let allFindings = [];
    let hasBlockingFindings = false;

    for (const bundlePath of bundlesToScan) {
      console.log(chalk.gray('\n  ⏳ Loading bundle...'));
      const code = loadBundle(bundlePath);
      console.log(chalk.green(`  ✓ Loaded ${Math.round(Buffer.byteLength(code, 'utf8') / 1024).toLocaleString()} KB`));
      
      const sourcemap = opts.sourcemap ? readJsonSafe(path.resolve(opts.sourcemap)) : null;

      const meta = {
        file: bundlePath,
        sizeBytes: Buffer.byteLength(code, 'utf8'),
        hasSourceMapURL: /sourceMappingURL=/.test(code),
        sourcemapLoaded: !!sourcemap,
        scannedAt: new Date().toISOString(),
        runtimeHint: detectRuntime(code),
      };

      // Scanning animation
      console.log(chalk.cyan('\n  🔍 Running security scan'));
      console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
      
      const findingsRaw = [];
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      
      for (let i = 0; i < RULES.length; i++) {
        const rule = RULES[i];
        
        // Show progress
        const progress = Math.round(((i + 1) / RULES.length) * 100);
        const barLength = 30;
        const filled = Math.round((progress / 100) * barLength);
        const empty = barLength - filled;
        
        // Gradient progress bar
        const barColor = progress < 33 ? chalk.cyan : progress < 66 ? chalk.blue : chalk.green;
        const bar = barColor('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
        
        process.stdout.write(`\r  ${bar} ${chalk.bold.white(progress + '%')} ${chalk.gray('│')} ${chalk.gray(rule.title.padEnd(35).slice(0, 35))}`);
        
        const res = rule.run(code).map((f) => ({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          ...f,
        }));
        
        // Real-time detection alerts - only for CRITICAL and HIGH
        if (res.length > 0) {
          // Count by severity
          if (rule.severity === 'critical') {
            criticalCount += res.length;
            process.stdout.write('\r' + ' '.repeat(120) + '\r'); // Clear line
            console.log(`  🔥 Found ${chalk.bold.white(res.length)} ${chalk.bold.magenta('CRITICAL')} ${chalk.gray('·')} ${chalk.white(rule.title)}`);
          } else if (rule.severity === 'high') {
            highCount += res.length;
            process.stdout.write('\r' + ' '.repeat(120) + '\r'); // Clear line
            console.log(`  ⚠️  Found ${chalk.bold.white(res.length)} ${chalk.red('HIGH')} ${chalk.gray('·')} ${chalk.white(rule.title)}`);
          } else if (rule.severity === 'medium') {
            mediumCount += res.length;
          } else if (rule.severity === 'low') {
            lowCount += res.length;
          }
        }
        
        findingsRaw.push(...res);
        if (findingsRaw.length >= opts.maxFindings) break;
      }
      
      // Clear progress line
      process.stdout.write('\r' + ' '.repeat(120) + '\r');
      console.log('');
      
      // Show medium/low counts if any
      if (mediumCount > 0 || lowCount > 0) {
        const counts = [];
        if (mediumCount > 0) counts.push(`${chalk.yellow(mediumCount)} medium`);
        if (lowCount > 0) counts.push(`${chalk.blue(lowCount)} low`);
        console.log(chalk.gray(`  └─ ${counts.join(', ')} severity finding(s)\n`));
      } else {
        console.log('');
      }
      
      // Scan complete message - compact format
      if (criticalCount > 0) {
        console.log(chalk.magenta(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.magenta(`  │`) + `  🚨  ${chalk.bold.magenta(`${criticalCount} CRITICAL`)} ${chalk.magenta('issue(s) detected')}`.padEnd(61) + chalk.magenta(`│`));
        console.log(chalk.magenta(`  └${'─'.repeat(50)}┘`));
      } else if (highCount > 0) {
        console.log(chalk.red(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.red(`  │`) + `  ⚠️   ${chalk.bold.red(`${highCount} HIGH`)} ${chalk.red('severity issue(s) detected')}`.padEnd(62) + chalk.red(`│`));
        console.log(chalk.red(`  └${'─'.repeat(50)}┘`));
      } else if (mediumCount > 0) {
        console.log(chalk.yellow(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.yellow(`  │`) + `  ⚡  ${chalk.bold.yellow(`${mediumCount} MEDIUM`)} ${chalk.yellow('issue(s) detected')}`.padEnd(62) + chalk.yellow(`│`));
        console.log(chalk.yellow(`  └${'─'.repeat(50)}┘`));
      } else {
        console.log(chalk.green(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.green(`  │`) + `  ✨  ${chalk.bold.green('Scan complete - no high-severity issues')}  `.padEnd(61) + chalk.green(`│`));
        console.log(chalk.green(`  └${'─'.repeat(50)}┘`));
      }

      // Deduplicate near-identical matches
      const dedupKey = (f) => `${f.id}:${f.match || f.message}:${Math.floor((f.position || 0) / 50)}`;
      const dedup = new Map();
      for (const f of findingsRaw) {
        const k = dedupKey(f);
        if (!dedup.has(k)) dedup.set(k, f);
      }
      const findings = [...dedup.values()];

      // Sort by severity then position
      findings.sort((a, b) => {
        const sev = SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
        if (sev !== 0) return sev;
        return (a.position || 0) - (b.position || 0);
      });

      // Console output
      if (bundlesToScan.length > 1) {
        console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}`));
      }
      const fileName = path.basename(meta.file);
      const fileDir = path.relative(process.cwd(), path.dirname(meta.file));
      console.log(chalk.bold.cyan(`\n  📦 Bundle Analysis`));
      console.log(chalk.gray(`  ╭${'─'.repeat(86)}╮`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📄 File:     `) + chalk.white(fileName.length > 66 ? fileName.slice(0, 63) + '...' : fileName.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📁 Location: `) + chalk.gray((fileDir || '.').padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`💾 Size:     `) + chalk.yellow(`${Math.round(meta.sizeBytes / 1024).toLocaleString()} KB`.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`⚙️  Runtime:  `) + chalk.white(meta.runtimeHint.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`🗺️  Source:   `) + (meta.hasSourceMapURL ? chalk.green('✓ SourceMap URL found') : chalk.gray('✗ No source map')).padEnd(77) + chalk.gray(` │`));
      console.log(chalk.gray(`  ╰${'─'.repeat(86)}╯`));
      console.log('');

      // Filter findings for display based on --show-level
      const showLevel = (opts.showLevel || 'medium').toLowerCase();
      const displayFindings = findings.filter(f => severityGte(f.severity, showLevel));
      
      // Show severity breakdown for ALL findings
      const severityCounts = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      if (findings.length === 0) {
        console.log(chalk.green(`  ╭${'─'.repeat(50)}╮`));
        console.log(chalk.green(`  │`) + chalk.green.bold(`  ✅  No security findings! Bundle looks clean.    `).padEnd(61) + chalk.green(`│`));
        console.log(chalk.green(`  ╰${'─'.repeat(50)}╯\n`));
      } else {
        console.log(chalk.bold.white(`  📊 Scan Results`));
        console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
        console.log(chalk.white(`  ${chalk.bold('Total Findings:')} ${chalk.cyan(findings.length)}\n`));
        
        // Show breakdown first
        console.log(chalk.gray(`  Severity Breakdown:`));
        console.log(chalk.gray(`  ╭${'─'.repeat(36)}╮`));
        if (severityCounts.critical) console.log(chalk.gray(`  │ `) + chalk.bold.magenta(` 🔥 CRITICAL   `) + chalk.magenta(`${severityCounts.critical}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.high) console.log(chalk.gray(`  │ `) + chalk.red.bold(` ⚠️  HIGH       `) + chalk.red(`${severityCounts.high}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.medium) console.log(chalk.gray(`  │ `) + chalk.yellow.bold(` ⚡ MEDIUM     `) + chalk.yellow(`${severityCounts.medium}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.low) console.log(chalk.gray(`  │ `) + chalk.blue.bold(` ℹ️  LOW        `) + chalk.blue(`${severityCounts.low}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.info) console.log(chalk.gray(`  │ `) + chalk.cyan.bold(` 💡 INFO       `) + chalk.cyan(`${severityCounts.info}`.padStart(3)) + chalk.gray('                │'));
        console.log(chalk.gray(`  ╰${'─'.repeat(36)}╯\n`));
        
        // Display filtered findings
        if (displayFindings.length === 0) {
          console.log(chalk.green(`  ✅ No findings at or above ${chalk.bold(showLevel.toUpperCase())} level`));
          console.log(chalk.gray(`  ${findings.length} lower-severity finding(s) hidden · Use --show-level to adjust\n`));
        } else {
          console.log(chalk.bold.white(`  📋 Detailed Findings`) + chalk.gray(` (${displayFindings.length} shown · >= ${showLevel.toUpperCase()})`));
          console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
          console.log(formatTable(displayFindings));
          console.log('');
        }
        
        // Mention JSON export if there are more findings
        if (displayFindings.length < findings.length) {
          console.log(chalk.gray(`  💡 ${findings.length - displayFindings.length} additional lower-severity finding(s) hidden · Use ${chalk.white('--show-level')} to view all\n`));
        }
      }

      allFindings.push(...findings.map(f => ({ ...f, bundle: bundlePath })));

      // JSON report per bundle (contains ALL findings, not filtered)
      if (opts.json !== false && bundlesToScan.length === 1) {
        const report = { 
          meta, 
          findings,
          summary: {
            total: findings.length,
            severityBreakdown: severityCounts,
            displayedOnScreen: displayFindings.length,
            showLevel: showLevel
          }
        };
        fs.writeFileSync(path.resolve(opts.json), JSON.stringify(report, null, 2), 'utf8');
        console.log(chalk.cyan(`  📄 Full report (${chalk.bold.white(findings.length)} findings) → `) + chalk.bold.white(opts.json));
      }

      // Check fail level
      const failLevel = (opts.failLevel || 'medium').toLowerCase();
      const hasBlocking = findings.some((f) => severityGte(f.severity, failLevel));
      if (hasBlocking) hasBlockingFindings = true;
    }

    // Multi-bundle JSON report (contains ALL findings)
    if (opts.json !== false && bundlesToScan.length > 1) {
      const overallSeverity = allFindings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      const report = {
        scannedAt: new Date().toISOString(),
        bundles: bundlesToScan.length,
        totalFindings: allFindings.length,
        findings: allFindings,
        summary: {
          severityBreakdown: overallSeverity,
          showLevel: opts.showLevel || 'medium'
        }
      };
      fs.writeFileSync(path.resolve(opts.json), JSON.stringify(report, null, 2), 'utf8');
      console.log(chalk.cyan(`  📄 Full report (${chalk.bold.white(allFindings.length)} findings) → `) + chalk.bold.white(opts.json));
    }

    // Summary
    if (bundlesToScan.length > 1) {
      console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}`));
      console.log(chalk.bold.white(`\n  📊 Overall Summary\n`));
      console.log(chalk.gray(`  ╭${'─'.repeat(86)}╮`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📦 Bundles Scanned: `) + chalk.bold.white(bundlesToScan.length.toString().padEnd(64)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`🔍 Total Findings:  `) + chalk.bold.yellow(allFindings.length.toString().padEnd(64)) + chalk.gray(` │`));
      
      // Overall severity breakdown
      const overallSeverity = allFindings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      if (Object.keys(overallSeverity).length > 0) {
        console.log(chalk.gray(`  ├${'─'.repeat(86)}┤`));
        if (overallSeverity.critical) console.log(chalk.gray(`  │ `) + chalk.bold.magenta(` 🔥 CRITICAL   `) + chalk.magenta(`${overallSeverity.critical}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.high) console.log(chalk.gray(`  │ `) + chalk.red.bold(` ⚠️  HIGH       `) + chalk.red(`${overallSeverity.high}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.medium) console.log(chalk.gray(`  │ `) + chalk.yellow.bold(` ⚡ MEDIUM     `) + chalk.yellow(`${overallSeverity.medium}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.low) console.log(chalk.gray(`  │ `) + chalk.blue.bold(` ℹ️  LOW        `) + chalk.blue(`${overallSeverity.low}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.info) console.log(chalk.gray(`  │ `) + chalk.cyan.bold(` 💡 INFO       `) + chalk.cyan(`${overallSeverity.info}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
      }
      
      console.log(chalk.gray(`  ╰${'─'.repeat(86)}╯`));
    }

    // CI fail level
    const failLevel = (opts.failLevel || 'medium').toLowerCase();
    console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}\n`));
    
    if (hasBlockingFindings) {
      console.log(chalk.magenta(`  ╭${'─'.repeat(60)}╮`));
      console.log(chalk.magenta(`  │`) + `  ⛔  ${chalk.bold.magenta('SECURITY CHECK FAILED')}                           `.padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  ├${'─'.repeat(60)}┤`));
      console.log(chalk.magenta(`  │`) + chalk.white(`  Findings at or above ${chalk.bold.magenta(failLevel.toUpperCase())} level detected`).padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  │`) + chalk.gray(`  Please review and address security issues`).padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  ╰${'─'.repeat(60)}╯\n`));
      if (opts.json !== false) {
        console.log(chalk.cyan(`  📋 Full report: `) + chalk.bold.white(opts.json));
      }
      console.log(chalk.gray(`\n  Exit code: 1\n`));
      process.exit(1);
    } else {
      console.log(chalk.green(`  ╭${'─'.repeat(60)}╮`));
      console.log(chalk.green(`  │`) + `  ✅  ${chalk.bold.green('SECURITY CHECK PASSED')}                          `.padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  ├${'─'.repeat(60)}┤`));
      console.log(chalk.green(`  │`) + chalk.white(`  No findings at or above ${chalk.bold.cyan(failLevel.toUpperCase())} level`).padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  │`) + chalk.gray(`  Bundle is ready for deployment!`).padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  ╰${'─'.repeat(60)}╯\n`));
      if (opts.json !== false) {
        console.log(chalk.cyan(`  📋 Full report: `) + chalk.bold.white(opts.json));
      }
      console.log(chalk.gray(`\n  Exit code: 0\n`));
      process.exit(0);
    }
  } catch (err) {
    console.error(chalk.red(`\n❌ Lupin error: ${err.message}`));
    process.exit(1);
  }
})();

/** ---------- Helpers ---------- */

function detectRuntime(code) {
  // Very rough hints to tell if bundle came from RN/Expo/Hermes
  if (/HermesInternal/.test(code)) return 'React Native (Hermes)';
  if (/__expo/.test(code) || /expo\./.test(code)) return 'Expo';
  if (/worklet/.test(code)) return 'Reanimated present';
  return 'Unknown';
}

