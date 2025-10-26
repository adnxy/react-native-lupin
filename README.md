# 🔒 Lupin Security Scanner

<div align="center">

[![npm version](https://img.shields.io/npm/v/lupin-security-scanner.svg)](https://www.npmjs.com/package/lupin-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/yourusername/lupin-security-scanner/workflows/Node.js%20CI/badge.svg)](https://github.com/yourusername/lupin-security-scanner/actions)

**Static Security Analysis for React Native & Expo Applications**

Detect hardcoded secrets, API keys, insecure patterns, and 60+ security vulnerabilities in your JavaScript bundles before they reach production.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [CLI](#-cli-usage) • [API](#-programmatic-api) • [Rules](#-security-rules) • [CI/CD](#-cicd-integration)

</div>

---

## 🎯 Why Lupin?

Mobile applications often ship with hardcoded secrets, insecure configurations, and vulnerable code patterns. **Lupin** scans your compiled JavaScript bundles to catch these issues before deployment, acting as your **last line of defense** in the security pipeline.

### What Lupin Detects

- 🔑 **60+ API Keys & Secrets** - OpenAI, AWS, Stripe, Firebase, Twilio, SendGrid, and more
- 🚨 **Critical Security Issues** - Hardcoded credentials, private keys, database URLs
- 🛡️ **React Native Vulnerabilities** - AsyncStorage misuse, insecure WebViews, SSL bypasses
- ⚡ **Code Injection Risks** - `eval()`, Function constructor, unsafe deep links
- 📊 **High-Entropy Strings** - Shannon entropy analysis for unknown secrets
- 🔐 **Mobile-Specific Issues** - Biometric bypasses, clipboard leaks, certificate pinning

---

## ✨ Features

- ✅ **Zero Configuration** - Auto-detects Expo & React Native CLI projects
- 🚀 **Fast Scanning** - Analyzes megabyte-sized bundles in seconds
- 🎨 **Beautiful CLI** - Real-time progress, severity colors, formatted tables
- 📦 **CI/CD Ready** - Exit codes, JSON reports, configurable fail levels
- 🔌 **Programmatic API** - Integrate into Node.js workflows
- 🎯 **60+ Security Rules** - Constantly updated detection patterns
- 🌐 **Multiple Bundles** - Scan iOS, Android, and web bundles together
- 📄 **Detailed Reports** - JSON export with full findings and metadata

---

## 📦 Installation

### NPM / Yarn / pnpm

```bash
# Install globally (recommended for CLI usage)
npm install -g lupin-security-scanner

# Or install as dev dependency
npm install --save-dev lupin-security-scanner
yarn add -D lupin-security-scanner
pnpm add -D lupin-security-scanner
```

### Requirements

- **Node.js**: ≥16.0.0
- **React Native** or **Expo** project

---

## 🚀 Quick Start

### 1. Build Your Bundle

**For Expo:**
```bash
npx expo export
```

**For React Native CLI:**
```bash
npx react-native bundle --platform ios --dev false --entry-file index.js --bundle-output ios/main.jsbundle
```

### 2. Run Lupin

```bash
# Auto-detect project and scan
lupin

# Scan all bundles without prompting
lupin --scan-all

# Scan specific bundle
lupin --bundle ./dist/bundle.js

# Generate JSON report
lupin --json security-report.json --fail-level high
```

---

## 🖥️ CLI Usage

### Basic Commands

```bash
# Auto-detect and scan
lupin

# Specify project type
lupin --type expo
lupin --type rn-cli

# Manual bundle scan
lupin --bundle path/to/bundle.js

# Scan all found bundles
lupin --scan-all
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-b, --bundle <path>` | Path to JS bundle (manual mode) | Auto-detect |
| `-t, --type <type>` | Project type: `expo` or `rn-cli` | Auto-detect |
| `--json <file>` | Export full JSON report | None |
| `--fail-level <level>` | Exit 1 if findings >= level | `medium` |
| `--show-level <level>` | Display findings >= level | `medium` |
| `--max-findings <n>` | Limit total findings | `5000` |
| `--scan-all` | Scan all bundles without prompt | `false` |
| `--no-color` | Disable colored output | `false` |

### Severity Levels

- `critical` - Immediate action required (API keys, credentials)
- `high` - Serious security risk (JWT tokens, SSL bypass)
- `medium` - Moderate risk (HTTP URLs, debug code)
- `low` - Minor issues (staging endpoints, dev markers)
- `info` - Informational (suggestions)

### Examples

```bash
# Production scan - only show high/critical
lupin --show-level high --fail-level high

# Generate report for security audit
lupin --json audit-$(date +%Y%m%d).json --scan-all

# CI/CD integration
lupin --fail-level critical --json report.json --no-color
```

---

## 📚 Programmatic API

Use Lupin in your Node.js applications, custom workflows, or build pipelines.

### Installation

```bash
npm install lupin-security-scanner
```

### Basic Usage

```javascript
import { scanBundle, detectProjectType, findBundles } from 'lupin-security-scanner';

// Scan a single bundle
const result = await scanBundle('./dist/bundle.js', {
  failLevel: 'high',
  showLevel: 'medium'
});

console.log(`Found ${result.totalFindings} security issues`);
console.log(`Critical: ${result.severityBreakdown.critical || 0}`);

if (result.hasBlockingFindings) {
  console.error('⛔ Security check failed!');
  process.exit(1);
}
```

### Auto-Discovery

```javascript
import { detectProjectType, findBundles, scanMultipleBundles } from 'lupin-security-scanner';

// Detect project type
const projectType = detectProjectType('./my-app');
console.log(`Project type: ${projectType}`); // 'expo' or 'rn-cli'

// Find all bundles
const bundles = await findBundles(projectType, './my-app');
console.log(`Found ${bundles.length} bundles`);

// Scan all bundles
const result = await scanMultipleBundles(bundles, {
  failLevel: 'high'
});

console.log(`Scanned ${result.totalBundles} bundles`);
console.log(`Total findings: ${result.totalFindings}`);
```

### Custom Security Workflow

```javascript
import { scanBundle } from 'lupin-security-scanner';
import fs from 'fs';

async function securityAudit() {
  const result = await scanBundle('./dist/production-bundle.js');

  // Filter critical findings
  const criticalIssues = result.allFindings.filter(
    f => f.severity === 'critical'
  );

  if (criticalIssues.length > 0) {
    // Generate detailed report
    const report = {
      timestamp: new Date().toISOString(),
      bundle: result.bundlePath,
      critical: criticalIssues,
      summary: result.severityBreakdown
    };

    fs.writeFileSync('security-audit.json', JSON.stringify(report, null, 2));

    // Notify team
    await notifySecurityTeam(criticalIssues);

    throw new Error(`Found ${criticalIssues.length} critical security issues`);
  }
}

await securityAudit();
```

### API Reference

#### `scanBundle(bundlePath, options)`

Scan a single JavaScript bundle for security issues.

**Parameters:**
- `bundlePath` (string): Path to the bundle file
- `options` (object):
  - `maxFindings` (number): Maximum findings to return (default: 5000)
  - `failLevel` (string): Severity threshold for failure (default: 'medium')
  - `showLevel` (string): Minimum severity to include (default: 'medium')

**Returns:** Promise<ScanResult>

```typescript
interface ScanResult {
  bundlePath: string;
  totalFindings: number;
  displayedFindings: number;
  findings: Finding[];
  allFindings: Finding[];
  hasBlockingFindings: boolean;
  failLevel: string;
  showLevel: string;
  severityBreakdown: Record<string, number>;
  meta: {
    sizeBytes: number;
    hasSourceMapURL: boolean;
    scannedAt: string;
    runtimeHint: string;
  };
}
```

#### `scanMultipleBundles(bundlePaths, options)`

Scan multiple bundles.

**Parameters:**
- `bundlePaths` (string[]): Array of bundle paths
- `options` (object): Same as `scanBundle`

**Returns:** Promise<MultiBundleScanResult>

#### `detectProjectType(baseDir?)`

Detect if a directory contains an Expo or React Native CLI project.

**Parameters:**
- `baseDir` (string): Directory to check (default: `process.cwd()`)

**Returns:** `'expo' | 'rn-cli' | null`

#### `findBundles(projectType, baseDir?)`

Find all bundle files for a project type.

**Parameters:**
- `projectType` (string): `'expo'` or `'rn-cli'`
- `baseDir` (string): Directory to search (default: `process.cwd()`)

**Returns:** Promise<string[]>

---

## 🛡️ Security Rules

Lupin includes **60+ security rules** across multiple categories:

### 🔑 API Keys & Secrets (25+ providers)

- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Google AI (Gemini, PaLM)
- AWS Access Keys
- Stripe Secret Keys
- Twilio Credentials
- SendGrid API Keys
- Firebase API Keys
- OAuth Client Secrets
- GitHub Tokens
- And 15+ more...

### 🚨 Critical Vulnerabilities

- Hardcoded admin credentials
- Private key exposure
- Database connection strings
- Payment card data handling
- Encryption key exposure

### 🛡️ React Native Security

- AsyncStorage sensitive data
- Redux/State management issues
- Unencrypted Realm databases
- WebView security (XSS, injection)
- Deep linking vulnerabilities
- Biometric bypass risks
- SSL/TLS verification disabled
- Certificate pinning missing

### ⚡ Code Execution Risks

- `eval()` usage
- Function constructor
- Unsafe deep link handling
- WebView JavaScript bridge

### 📊 Debug & Configuration

- Development markers in production
- Console logging sensitive data
- Staging/test endpoints
- Environment variable leaks
- Hardcoded API endpoints

### 🔐 Mobile-Specific

- Clipboard sensitive data
- Custom URL scheme security
- Push notification key exposure
- Third-party SDK key checks

---

## 🔄 CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  lupin-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Build Expo bundle
        run: npx expo export --platform ios

      - name: Install Lupin
        run: npm install -g lupin-security-scanner

      - name: Run Security Scan
        run: lupin --scan-all --fail-level high --json security-report.json

      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: node:18
  script:
    - npm ci
    - npx expo export --platform ios
    - npm install -g lupin-security-scanner
    - lupin --scan-all --fail-level high --json security-report.json
  artifacts:
    reports:
      paths:
        - security-report.json
    when: always
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run: npm ci
      - run: npx expo export --platform ios
      - run: npm install -g lupin-security-scanner
      - run: lupin --scan-all --fail-level high --json security-report.json
      - store_artifacts:
          path: security-report.json

workflows:
  build:
    jobs:
      - security-scan
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔒 Running Lupin security scan..."

# Build bundle (adjust for your project)
npx expo export --platform ios > /dev/null 2>&1

# Run scan
lupin --scan-all --fail-level critical --no-color

if [ $? -ne 0 ]; then
  echo "⛔ Security scan failed! Fix critical issues before committing."
  exit 1
fi

echo "✅ Security scan passed!"
```

---

## 📖 Best Practices

### 1. **Scan Before Every Release**

```bash
# Add to package.json scripts
{
  "scripts": {
    "security": "lupin --scan-all --fail-level high",
    "prerelease": "npm run security"
  }
}
```

### 2. **Use Environment Variables**

Never hardcode secrets in source code. Use environment variables and ensure they're not bundled:

```javascript
// ❌ BAD
const API_KEY = 'sk-proj-abc123...';

// ✅ GOOD
const API_KEY = process.env.EXPO_PUBLIC_API_KEY;
```

### 3. **Configure Fail Levels by Environment**

```bash
# Development - show all issues
lupin --show-level info

# Staging - fail on high/critical
lupin --fail-level high

# Production - fail on medium and above
lupin --fail-level medium
```

### 4. **Review JSON Reports**

```javascript
const report = require('./security-report.json');

// Filter by rule type
const apiKeyLeaks = report.findings.filter(f => 
  f.id.startsWith('KEY-')
);

// Review entropy findings
const highEntropy = report.findings.filter(f => 
  f.id === 'KEY-OTHER' && f.meta?.entropy > 4.5
);
```

### 5. **Whitelist False Positives**

Some findings may be false positives (e.g., public Firebase config). Document these:

```javascript
// FALSE POSITIVE WHITELIST
// Finding: KEY-FIREBASE (Firebase API Key)
// Reason: Public Firebase config, protected by security rules
// Approved: 2025-10-26
// Reviewer: security-team@company.com
const firebaseConfig = {
  apiKey: "AIza..."
};
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/yourusername/lupin-security-scanner.git
cd lupin-security-scanner
npm install
npm test
```

### Adding New Rules

1. Add rule to `RULES` array in `bin/lupin.js`
2. Include test cases
3. Update documentation
4. Submit PR with description

---

## 📝 License

MIT © [Your Name](https://github.com/yourusername)

---

## 🔗 Links

- **npm**: [https://www.npmjs.com/package/lupin-security-scanner](https://www.npmjs.com/package/lupin-security-scanner)
- **GitHub**: [https://github.com/yourusername/lupin-security-scanner](https://github.com/yourusername/lupin-security-scanner)
- **Issues**: [https://github.com/yourusername/lupin-security-scanner/issues](https://github.com/yourusername/lupin-security-scanner/issues)
- **Documentation**: [https://github.com/yourusername/lupin-security-scanner/tree/main/docs](https://github.com/yourusername/lupin-security-scanner/tree/main/docs)

---

## 🙏 Acknowledgments

- Inspired by security best practices from OWASP Mobile Security Project
- Built for the React Native and Expo community
- Named after Arsène Lupin, the gentleman thief who knew all the secrets

---

## 📊 Example Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                   🔒 LUPIN - Bundle Security Scanner                          ║
║                   React Native & Expo Security Auditor                        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

✓ Detected project type: expo
✓ Found 2 bundle file(s)

  ┌────────────────────────────────────────────────────────────────────────────┐
  │ 1. dist/_expo/static/js/ios/entry-abc123.js               1,245 KB │
  │ 2. dist/_expo/static/js/android/entry-def456.js           1,198 KB │
  └────────────────────────────────────────────────────────────────────────────┘

  ⏳ Loading bundle...
  ✓ Loaded 1,245 KB

  🔍 Running security scan...

  ● Found 1 CRITICAL issue(s): OpenAI API Key
  ● Found 2 HIGH issue(s): AWS Access Key
  ● Found 5 MEDIUM issue(s): Insecure HTTP URLs

  🚨 CRITICAL: 1 critical security issue(s) detected!

  📊 Total Findings: 23

  Severity Breakdown (All Findings):
  ┌────────────────────────────────┐
  │  CRITICAL  1                   │
  │  HIGH      3                   │
  │  MEDIUM    12                  │
  │  LOW       5                   │
  │  INFO      2                   │
  └────────────────────────────────┘

════════════════════════════════════════════════════════════════════════════════

  ⛔ SECURITY CHECK FAILED

  Findings at or above fail level "MEDIUM" detected.
  Please review and address the security issues before deploying.

  📋 Review full details in: security-report.json

  Exit code: 1
```

---

<div align="center">

**Made with 🔐 for React Native & Expo developers**

[⬆ back to top](#-lupin-security-scanner)

</div>
