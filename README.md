# React Native Lupin - Security Scanner

**Static security analysis for React Native and Expo applications.**

Automated detection of security vulnerabilities in compiled JavaScript bundles, including API keys, secrets, insecure code patterns, and mobile-specific security issues.

[![npm version](https://img.shields.io/npm/v/react-native-lupin.svg)](https://www.npmjs.com/package/react-native-lupin)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents

- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [Security Coverage](#security-coverage)
- [CI/CD Integration](#cicd-integration)
- [JSON Report Format](#json-report-format)
- [Best Practices](#best-practices)

---

## Installation

### Global Installation (Recommended)

```bash
# Install globally with npm
npm install -g react-native-lupin

# Install globally with yarn
yarn global add react-native-lupin
```

After installation, simply run:
```bash
lupin
```

### Run Without Installing

```bash
# Using npx
npx react-native-lupin

# Using yarn
yarn dlx react-native-lupin
```

---

## Quick Start

**Step 1:** Generate a bundle for your project

**Step 2:** Run Lupin
```bash
lupin
```

That's it! Lupin will auto-detect your project type and scan your bundles.

---

## Prerequisites

**Important:** Lupin scans compiled JavaScript bundles, not source code. You must generate a bundle before scanning.

### For Expo Projects

```bash
# Generate bundle for iOS
npx expo export --platform ios

# Generate bundle for Android
npx expo export --platform android

# Generate for both platforms
npx expo export
```

### For React Native CLI Projects

```bash
# Android
cd android && ./gradlew bundleRelease

# iOS
npx react-native bundle \
  --platform ios \
  --dev false \
  --entry-file index.js \
  --bundle-output ios/main.jsbundle
```

---

## Usage

### Basic Scan (Automatic)

After installation, simply run:

```bash
lupin
```

✨ Lupin will automatically:
- Detect your project type (Expo or React Native CLI)
- Find compiled bundles in your project
- Scan for security vulnerabilities
- Generate a JSON report with all findings

**Note:** JSON reports are generated automatically by default with filename `lupin-report-{timestamp}.json`.

### Specify Bundle Path

```bash
lupin --bundle path/to/bundle.js
```

### Filter by Severity

```bash
# Show only critical issues
lupin --show-level critical

# Show high and above
lupin --show-level high
```

### Disable JSON Report

```bash
lupin --no-json
```

### Custom JSON Report Name

```bash
lupin --json my-security-report.json
```

### CI/CD Mode

```bash
# Non-interactive, fail on high severity
lupin --scan-all --fail-level high
```

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-b, --bundle <path>` | Path to specific bundle file | Auto-detect |
| `-t, --type <type>` | Project type: `expo` or `rn-cli` | Auto-detect |
| `--json [file]` | Generate JSON report (enabled by default) | `lupin-report-{timestamp}.json` |
| `--no-json` | Disable automatic JSON generation | - |
| `--show-level <level>` | Display threshold: `info\|low\|medium\|high\|critical` | `medium` |
| `--fail-level <level>` | Exit code threshold | `medium` |
| `--scan-all` | Scan all bundles without prompting | `false` |
| `--max-findings <n>` | Limit number of findings | `5000` |
| `--no-color` | Disable colored output | `false` |
| `-h, --help` | Display help information | - |

---

## Security Coverage

### Critical Severity (15 rules)

**API Keys & Credentials:**
- OpenAI, Claude (Anthropic), Google Gemini API keys
- Stripe secret keys (live)
- Twilio Account SID/Auth Token
- SendGrid API keys
- OAuth client secrets
- Private keys (RSA, PEM)
- Database connection strings
- Facebook/Twitter API secrets
- Payment card data (PCI-DSS)
- Hardcoded admin credentials
- Encryption keys

### High Severity (18 rules)

**Code Execution & Storage:**
- `eval()` function usage
- `new Function()` constructor
- Sensitive data in AsyncStorage
- JWT tokens embedded in code
- AWS Access Keys
- GitHub Personal Access Tokens
- Slack tokens
- Algolia admin keys
- SSL/TLS verification disabled
- Unencrypted Realm databases
- WebView JavaScript bridges
- Unsafe deep link handling
- Hugging Face tokens
- Push notification server keys
- Environment secrets in bundle

### Medium Severity (15 rules)

**Configuration & Logging:**
- Console logging of sensitive data
- HTTP URLs (should use HTTPS)
- Redux/state with passwords
- Sentry DSN exposure
- Firebase API keys
- Mapbox tokens
- WebView security misconfigurations
- Clipboard operations with sensitive data
- Debug mode enabled
- Biometric authentication bypass risks
- Custom URL scheme vulnerabilities
- SQLite without encryption
- Analytics write keys
- Third-party SDK keys

### Low Severity (7 rules)

**Development & Best Practices:**
- Hardcoded API endpoints
- Development markers in production
- Staging/test endpoint references
- Certificate pinning not detected
- Expo SecureStore not utilized

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm install
      
      - name: Generate bundle (Expo)
        run: npx expo export --platform ios
      
      - name: Run security scan
        run: npx react-native-lupin --scan-all --fail-level high
      
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: lupin-report-*.json
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: node:18
  script:
    - npm install
    - npx expo export --platform ios
    - npx react-native-lupin --scan-all --fail-level high
  artifacts:
    when: always
    paths:
      - lupin-report-*.json
    expire_in: 30 days
```

### Expo EAS Build Hook

Add to `eas.json`:

```json
{
  "build": {
    "production": {
      "postExport": [
        {
          "command": "npx react-native-lupin --scan-all --fail-level high"
        }
      ]
    }
  }
}
```

### NPM Scripts

Add to `package.json`:

```json
{
  "scripts": {
    "security": "lupin --show-level high",
    "security:full": "lupin --show-level info",
    "security:ci": "lupin --scan-all --fail-level high",
    "prebuild": "npm run security:ci"
  }
}
```

---

## JSON Report Format

**JSON reports are automatically generated by default** with timestamped filenames. Each report contains detailed security findings:

```json
{
  "meta": {
    "file": "dist/_expo/static/js/ios/entry-abc123.js",
    "sizeBytes": 3051520,
    "scannedAt": "2025-10-26T14:30:45.000Z",
    "runtimeHint": "React Native (Hermes)",
    "hasSourceMapURL": true
  },
  "findings": [
    {
      "id": "KEY-OPENAI",
      "title": "OpenAI API Key",
      "severity": "critical",
      "message": "OpenAI API key detected. Remove immediately.",
      "position": 12345,
      "snippet": "...surrounding code...",
      "match": "sk-proj-..."
    }
  ],
  "summary": {
    "total": 184,
    "severityBreakdown": {
      "critical": 1,
      "high": 8,
      "medium": 175,
      "low": 0,
      "info": 0
    },
    "displayedOnScreen": 9,
    "showLevel": "high"
  }
}
```

---

## Best Practices

### Recommended Configuration

**For Development:**
```bash
lupin --show-level high
```
Focus on critical and high severity issues during active development.

**For Production:**
```bash
lupin --scan-all --fail-level medium --json production-scan.json
```
Comprehensive scan with medium threshold for production deployments.

**For Pre-commit:**
```bash
lupin --fail-level critical
```
Block commits only for critical issues to maintain developer velocity.

### Security Guidelines

#### ✓ Do:
- Use `SecureStore` (Expo) or `react-native-keychain` for tokens
- Encrypt local databases (Realm with `encryptionKey`, SQLCipher)
- Validate and sanitize all deep link parameters
- Use HTTPS for all network requests
- Remove all `console.log` statements in production builds
- Keep API keys and secrets on backend servers
- Implement certificate pinning for sensitive operations
- Use environment variables properly (never bundle secrets)

#### ✗ Don't:
- Store tokens or passwords in AsyncStorage
- Disable SSL certificate verification
- Use `eval()` or `new Function()` for dynamic code execution
- Log sensitive data to console
- Hardcode credentials in source code
- Store payment card data locally
- Expose private keys in application bundles
- Trust deep link data without validation

---

## Common Findings

Based on analysis of production React Native applications:

| Issue | Frequency | Severity |
|-------|-----------|----------|
| AsyncStorage misuse (sensitive data) | 85% | High |
| Debug code in production | 70% | Medium |
| Console logging of credentials | 60% | Medium |
| HTTP URLs instead of HTTPS | 40% | Medium |
| Hardcoded API endpoints | 30% | Low |
| Exposed API keys | 15% | Critical |
| eval() usage | 10% | High |
| Unencrypted databases | 5% | High |

---

## Performance

- Scans 3MB bundles in ~2-3 seconds
- Shannon entropy algorithm for secret detection
- Automatic deduplication of findings
- 60+ security rules with minimal false positives
- Memory efficient for large bundles

---

## Compatibility

- **Node.js:** 16.0.0 or higher
- **Expo:** SDK 45+
- **React Native:** 0.60+
- **Platforms:** macOS, Linux, Windows
- **CI/CD:** GitHub Actions, GitLab CI, CircleCI, Bitrise, Jenkins

---

## Contributing

Contributions are welcome. To add security rules or report issues:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Commit your changes (`git commit -am 'Add new security rule'`)
4. Push to the branch (`git push origin feature/new-rule`)
5. Open a Pull Request

---

## License

MIT © adnxy

---

## Links

- **GitHub Repository:** https://github.com/adnxy/react-native-lupin
- **NPM Package:** https://www.npmjs.com/package/react-native-lupin
- **Issue Tracker:** https://github.com/adnxy/react-native-lupin/issues
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

---

## Support

For bug reports and feature requests, please use the [issue tracker](https://github.com/adnxy/react-native-lupin/issues).

Star the repository if you find this tool useful for securing your React Native applications.
