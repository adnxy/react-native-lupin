# 🚀 Quick Start Guide

Welcome to Lupin Security Scanner! This guide will help you get started in minutes.

## Installation

```bash
# Install globally for CLI usage
npm install -g lupin-security-scanner

# Or as a project dev dependency
npm install --save-dev lupin-security-scanner
```

## Basic Usage

### 1. Build Your Bundle

**For Expo:**
```bash
npx expo export
```

**For React Native CLI:**
```bash
npx react-native bundle \
  --platform ios \
  --dev false \
  --entry-file index.js \
  --bundle-output ios/main.jsbundle
```

### 2. Scan for Security Issues

```bash
# Auto-detect project and scan
lupin

# Or scan a specific bundle
lupin --bundle ./dist/bundle.js

# Generate a JSON report
lupin --json security-report.json
```

## Example Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                   🔒 LUPIN - Bundle Security Scanner                          ║
║                   React Native & Expo Security Auditor                        ║
╚═══════════════════════════════════════════════════════════════════════════════╝

✓ Detected project type: expo
✓ Found 2 bundle file(s)

  ⏳ Loading bundle...
  ✓ Loaded 1,245 KB

  🔍 Running security scan...

  ● Found 1 CRITICAL issue(s): OpenAI API Key
  ● Found 2 HIGH issue(s): AWS Access Key

  📊 Total Findings: 15

  Severity Breakdown:
  ┌────────────────────────────────┐
  │  CRITICAL  1                   │
  │  HIGH      3                   │
  │  MEDIUM    8                   │
  │  LOW       3                   │
  └────────────────────────────────┘
```

## What Gets Detected?

✅ **60+ Security Rules Including:**

- 🔑 API Keys (OpenAI, AWS, Stripe, Firebase, etc.)
- 🚨 Hardcoded credentials and secrets
- 🛡️ React Native vulnerabilities
- ⚡ Code injection risks (eval, Function constructor)
- 📊 High-entropy strings (unknown secrets)
- 🔐 Mobile-specific issues (AsyncStorage, WebView, SSL)

## Common Commands

```bash
# Quick scan - fail on critical only
lupin --fail-level critical

# Comprehensive scan - fail on medium and above
lupin --fail-level medium

# Development scan - show all issues
lupin --show-level info --fail-level critical

# Production scan - strict checking
lupin --scan-all --fail-level high --json production-report.json

# Scan specific bundle
lupin --bundle ./ios/main.jsbundle --type rn-cli

# Multiple bundles
lupin --scan-all  # Auto-finds and scans all bundles
```

## Exit Codes

- `0` - No security issues at or above fail level ✅
- `1` - Security issues found that meet or exceed fail level ❌

## CI/CD Integration

Add to your pipeline:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    npm install -g lupin-security-scanner
    npx expo export
    lupin --scan-all --fail-level high
```

## Programmatic Usage

```javascript
import { scanBundle } from 'lupin-security-scanner';

const result = await scanBundle('./dist/bundle.js', {
  failLevel: 'high',
  showLevel: 'medium'
});

if (result.hasBlockingFindings) {
  console.error('❌ Security issues found!');
  process.exit(1);
}
```

## What's Next?

- 📖 Read the [Full Documentation](README.md)
- 🔧 Explore the [API Documentation](docs/API.md)
- 🧪 Learn about [Testing](docs/TESTING.md)
- 🤝 See [Contributing Guidelines](CONTRIBUTING.md)

## Getting Help

- 💬 [GitHub Discussions](https://github.com/yourusername/lupin-security-scanner/discussions)
- 🐛 [Report Issues](https://github.com/yourusername/lupin-security-scanner/issues)
- 📧 Email: support@yourdomain.com

---

**Ready to secure your mobile app? Run your first scan now!**

```bash
lupin
```

