/**
 * Lupin Security Scanner - Programmatic API
 * 
 * Use this module to integrate Lupin into your Node.js applications,
 * CI/CD pipelines, or custom security workflows.
 */

import fs from 'fs';
import path from 'path';
import { glob } from 'glob';

/**
 * Scan a bundle file for security issues
 * 
 * @param {string} bundlePath - Path to the JavaScript bundle file
 * @param {Object} options - Scan options
 * @param {number} [options.maxFindings=5000] - Maximum number of findings to return
 * @param {string} [options.failLevel='medium'] - Minimum severity level to fail (info|low|medium|high|critical)
 * @param {string} [options.showLevel='medium'] - Minimum severity level to include in results
 * @returns {Promise<ScanResult>} Scan results
 * 
 * @example
 * ```js
 * import { scanBundle } from 'lupin-security-scanner';
 * 
 * const result = await scanBundle('./dist/bundle.js', {
 *   failLevel: 'high',
 *   showLevel: 'medium'
 * });
 * 
 * if (result.hasBlockingFindings) {
 *   console.error('Security issues found!');
 *   process.exit(1);
 * }
 * ```
 */
export async function scanBundle(bundlePath, options = {}) {
  const {
    maxFindings = 5000,
    failLevel = 'medium',
    showLevel = 'medium'
  } = options;

  if (!fs.existsSync(bundlePath)) {
    throw new Error(`Bundle not found: ${bundlePath}`);
  }

  const code = fs.readFileSync(bundlePath, 'utf8');
  const findings = [];

  // Import rules dynamically
  const rules = await getRules();

  // Run all rules
  for (const rule of rules) {
    const res = rule.run(code).map((f) => ({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      ...f,
    }));

    findings.push(...res);
    if (findings.length >= maxFindings) break;
  }

  // Deduplicate findings
  const deduped = deduplicateFindings(findings);

  // Sort by severity
  const sorted = sortFindings(deduped);

  // Filter by show level
  const filtered = filterBySeverity(sorted, showLevel);

  // Check if there are blocking findings
  const hasBlockingFindings = sorted.some(f => severityGte(f.severity, failLevel));

  // Calculate severity breakdown
  const severityBreakdown = sorted.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return {
    bundlePath,
    totalFindings: sorted.length,
    displayedFindings: filtered.length,
    findings: filtered,
    allFindings: sorted,
    hasBlockingFindings,
    failLevel,
    showLevel,
    severityBreakdown,
    meta: {
      sizeBytes: Buffer.byteLength(code, 'utf8'),
      hasSourceMapURL: /sourceMappingURL=/.test(code),
      scannedAt: new Date().toISOString(),
      runtimeHint: detectRuntime(code),
    }
  };
}

/**
 * Scan multiple bundles
 * 
 * @param {string[]} bundlePaths - Array of bundle paths
 * @param {Object} options - Scan options (same as scanBundle)
 * @returns {Promise<MultiBundleScanResult>}
 * 
 * @example
 * ```js
 * import { scanMultipleBundles } from 'lupin-security-scanner';
 * 
 * const result = await scanMultipleBundles([
 *   './dist/ios-bundle.js',
 *   './dist/android-bundle.js'
 * ], { failLevel: 'high' });
 * ```
 */
export async function scanMultipleBundles(bundlePaths, options = {}) {
  const results = [];

  for (const bundlePath of bundlePaths) {
    const result = await scanBundle(bundlePath, options);
    results.push(result);
  }

  const allFindings = results.flatMap(r => r.allFindings.map(f => ({ ...f, bundle: r.bundlePath })));
  const hasBlockingFindings = results.some(r => r.hasBlockingFindings);

  const severityBreakdown = allFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return {
    bundles: results,
    totalBundles: bundlePaths.length,
    totalFindings: allFindings.length,
    allFindings,
    hasBlockingFindings,
    severityBreakdown,
    scannedAt: new Date().toISOString()
  };
}

/**
 * Detect project type (Expo or React Native CLI)
 * 
 * @param {string} [baseDir=process.cwd()] - Base directory to check
 * @returns {string|null} 'expo', 'rn-cli', or null if not detected
 * 
 * @example
 * ```js
 * import { detectProjectType } from 'lupin-security-scanner';
 * 
 * const projectType = detectProjectType('./my-project');
 * console.log(`Project type: ${projectType}`); // 'expo' or 'rn-cli'
 * ```
 */
export function detectProjectType(baseDir = process.cwd()) {
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

/**
 * Find bundle files automatically
 * 
 * @param {string} projectType - 'expo' or 'rn-cli'
 * @param {string} [baseDir=process.cwd()] - Base directory to search
 * @returns {Promise<string[]>} Array of bundle file paths
 * 
 * @example
 * ```js
 * import { findBundles, detectProjectType } from 'lupin-security-scanner';
 * 
 * const projectType = detectProjectType();
 * const bundles = await findBundles(projectType);
 * console.log(`Found ${bundles.length} bundles`);
 * ```
 */
export async function findBundles(projectType, baseDir = process.cwd()) {
  const bundles = [];

  if (projectType === 'expo') {
    const patterns = [
      'dist/_expo/static/js/**/*.js',
      '.expo/static/js/**/*.js',
      'web-build/static/js/**/*.js'
    ];
    
    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => fs.statSync(f).size > 10000));
      } catch {}
    }
  } else if (projectType === 'rn-cli') {
    const patterns = [
      'android/app/build/generated/assets/react/**/index.android.bundle',
      'android/app/src/main/assets/index.android.bundle',
      'ios/build/**/main.jsbundle',
      'ios/main.jsbundle',
      '*.bundle'
    ];

    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => fs.statSync(f).size > 10000));
      } catch {}
    }
  }

  return [...new Set(bundles)];
}

/**
 * Get all available security rules
 * 
 * @returns {Promise<Array>} Array of security rules
 */
export async function getRules() {
  // Import rules from the CLI scanner
  // In a real implementation, you'd want to extract rules to a shared module
  return [];
}

// ===== Helper Functions =====

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

function severityGte(a, b) {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

function deduplicateFindings(findings) {
  const dedupKey = (f) => `${f.id}:${f.match || f.message}:${Math.floor((f.position || 0) / 50)}`;
  const dedup = new Map();
  
  for (const f of findings) {
    const k = dedupKey(f);
    if (!dedup.has(k)) dedup.set(k, f);
  }
  
  return [...dedup.values()];
}

function sortFindings(findings) {
  return findings.sort((a, b) => {
    const sev = SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
    if (sev !== 0) return sev;
    return (a.position || 0) - (b.position || 0);
  });
}

function filterBySeverity(findings, minLevel) {
  return findings.filter(f => severityGte(f.severity, minLevel));
}

function detectRuntime(code) {
  if (/HermesInternal/.test(code)) return 'React Native (Hermes)';
  if (/__expo/.test(code) || /expo\./.test(code)) return 'Expo';
  if (/worklet/.test(code)) return 'Reanimated present';
  return 'Unknown';
}

// ===== TypeScript Type Definitions (for JSDoc) =====

/**
 * @typedef {Object} Finding
 * @property {string} id - Rule ID (e.g., 'RN-001')
 * @property {string} title - Short title of the finding
 * @property {string} severity - Severity level (info|low|medium|high|critical)
 * @property {string} message - Detailed message about the finding
 * @property {number} position - Character position in the bundle
 * @property {string} [snippet] - Code snippet around the finding
 * @property {string} [match] - Matched text
 */

/**
 * @typedef {Object} ScanResult
 * @property {string} bundlePath - Path to the scanned bundle
 * @property {number} totalFindings - Total number of findings (all severities)
 * @property {number} displayedFindings - Number of findings matching showLevel
 * @property {Finding[]} findings - Findings matching showLevel filter
 * @property {Finding[]} allFindings - All findings regardless of showLevel
 * @property {boolean} hasBlockingFindings - Whether any findings meet or exceed failLevel
 * @property {string} failLevel - Minimum severity that causes failure
 * @property {string} showLevel - Minimum severity included in findings array
 * @property {Object} severityBreakdown - Count of findings by severity
 * @property {Object} meta - Bundle metadata
 */

/**
 * @typedef {Object} MultiBundleScanResult
 * @property {ScanResult[]} bundles - Results for each scanned bundle
 * @property {number} totalBundles - Number of bundles scanned
 * @property {number} totalFindings - Total findings across all bundles
 * @property {Finding[]} allFindings - All findings from all bundles
 * @property {boolean} hasBlockingFindings - Whether any bundle has blocking findings
 * @property {Object} severityBreakdown - Count of findings by severity across all bundles
 * @property {string} scannedAt - ISO timestamp of scan
 */

