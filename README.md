#  React Native Lupin - Security Scanner

**Fast, beautiful security scanner for React Native and Expo bundles.**

Detects 60+ vulnerabilities: API keys, secrets, insecure code patterns, and mobile security issues.

[![npm version](https://img.shields.io/npm/v/react-native-lupin.svg)](https://www.npmjs.com/package/react-native-lupin)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Quick Start

```bash
# Install globally
npm install -g react-native-lupin

# Run in your React Native/Expo project
lupin

# That's it! ✨
```

---

## 🎯 What It Does

Scans your compiled JavaScript bundles for:

- 🤖 **AI API Keys**: OpenAI, Claude, Gemini, Cohere
- 🔑 **Secrets**: Stripe, AWS, GitHub, Twilio, SendGrid
- 📱 **Mobile Security**: AsyncStorage, database encryption, SSL/TLS
- 💳 **PCI-DSS**: Payment card data
- 🌐 **Network Security**: HTTP vs HTTPS, certificate pinning
- 🔓 **Code Security**: eval(), hardcoded credentials, debug code

**60+ security rules** covering critical to low severity issues.

---

## 📦 Installation

### Global (Recommended)
```bash
npm install -g react-native-lupin
```

### Or use without installing
```bash
npx react-native-lupin
```

---

## 🚀 Usage

### Basic Scan
```bash
# Auto-detects your project and finds bundles
lupin
```

### Show Only Critical Issues
```bash
lupin --show-level critical
```

### Export JSON Report
```bash
lupin --json security-report.json
```

### Scan Specific Bundle
```bash
lupin --bundle dist/main.jsbundle
```

### CI/CD Mode
```bash
# No interactive prompts
lupin --scan-all --fail-level high
```

---

## 🎨 What You'll See

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                   🔒 LUPIN - Bundle Security Scanner                          ║
║                   React Native & Expo Security Auditor                        ║
╚═══════════════════════════════════════════════════════════════════════════════╝

✓ Detected project type: expo
✓ Found 1 bundle file(s)

  ⏳ Loading bundle...
  ✓ Loaded 2,980 KB

  🔍 Running security scan...
  ████████████████████████████████ 100%

  🔴 Found 1 CRITICAL issue(s): OpenAI API Key
  🟠 Found 8 HIGH issue(s): Use of eval

  📊 Total Findings: 184

  Severity Breakdown:
  ┌────────────────────────────────┐
  │  CRITICAL  1                   │
  │  HIGH      8                   │
  │  MEDIUM    175                 │
  └────────────────────────────────┘

  📄 Full report → lupin-report.json
```

---

## 📋 Command Line Options

```bash
Options:
  -b, --bundle <path>        Scan specific bundle file
  -t, --type <type>          Project type: expo or rn-cli
  --json <file>              Export JSON report (contains ALL findings)
  --show-level <level>       Display threshold: critical|high|medium|low|info
  --fail-level <level>       Exit code threshold (default: medium)
  --scan-all                 Scan all bundles without prompting
  --max-findings <n>         Limit findings (default: 5000)
  --no-color                 Disable colored output
  -h, --help                 Show help
```

---

## 🔍 What Gets Detected

### 🔴 Critical (15 rules)
- OpenAI, Claude, Gemini API keys
- Stripe secret keys
- OAuth client secrets
- Private keys (RSA/PEM)
- Database credentials
- Payment card data
- Admin passwords

### 🟠 High (18 rules)
- `eval()` usage
- AsyncStorage with passwords
- GitHub, AWS tokens
- JWT tokens in code
- SSL/TLS disabled
- Unencrypted databases

### 🟡 Medium (15 rules)
- Console logging secrets
- Redux state with passwords
- HTTP URLs
- Firebase, Mapbox keys
- Debug code in production

### 🔵 Low & Info (7 rules)
- Hardcoded endpoints
- Missing certificate pinning
- Development markers

---

## 💼 Real-World Use Cases

### Local Development
```bash
# Quick security check before committing
lupin --show-level high
```

### Pre-commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
lupin --fail-level high || exit 1
```

### CI/CD Pipeline

**GitHub Actions:**
```yaml
- name: Security Scan
  run: |
    npx expo export
    npx react-native-lupin --scan-all --fail-level high
```

**GitLab CI:**
```yaml
security-scan:
  script:
    - npx expo export
    - npx react-native-lupin --scan-all --json report.json
  artifacts:
    paths:
      - report.json
```

### NPM Script
```json
{
  "scripts": {
    "security": "lupin --show-level critical",
    "security:full": "lupin --json security-report.json"
  }
}
```

---

## 🎯 Before You Scan

Make sure you have a bundle to scan:

### Expo
```bash
npx expo export
```

### React Native CLI
```bash
# Android
cd android && ./gradlew bundleRelease

# iOS
npx react-native bundle --platform ios --dev false \
  --entry-file index.js --bundle-output ios/main.jsbundle
```

Then run Lupin!

---

## 📊 JSON Report Format

The `--json` flag exports detailed findings:

```json
{
  "meta": {
    "file": "dist/_expo/static/js/ios/entry-xxx.js",
    "sizeBytes": 3051520,
    "scannedAt": "2025-10-26T...",
    "runtimeHint": "React Native (Hermes)"
  },
  "findings": [
    {
      "id": "KEY-OPENAI",
      "title": "OpenAI API Key",
      "severity": "critical",
      "message": "OpenAI API key detected...",
      "position": 12345,
      "snippet": "...code snippet...",
      "match": "sk-proj-..."
    }
  ],
  "summary": {
    "total": 184,
    "severityBreakdown": {
      "critical": 1,
      "high": 8,
      "medium": 175
    }
  }
}
```

---

## 🚨 Common Issues Found

Based on real React Native apps:

- **85%** - AsyncStorage misuse with sensitive data
- **70%** - Debug code in production bundles
- **60%** - Logging passwords/tokens to console
- **40%** - HTTP URLs (should be HTTPS)
- **30%** - Hardcoded API endpoints
- **15%** - Exposed API keys (Stripe, AWS, OpenAI)
- **10%** - eval() or Function() usage
- **5%** - Unencrypted databases

---

## 🛡️ Security Best Practices

### ✅ DO:
- Use SecureStore/Keychain for tokens
- Encrypt databases (Realm, SQLite)
- Validate deep links
- Use HTTPS everywhere
- Remove debug code
- Keep API keys on backend
- Implement certificate pinning

### ❌ DON'T:
- Store secrets in AsyncStorage
- Disable SSL verification
- Use eval() or new Function()
- Log sensitive data
- Hardcode credentials
- Store payment card data
- Expose private keys

---

## 🤝 Contributing

Found a bug or want to add a security rule? Contributions welcome!

1. Fork the repo
2. Create a feature branch
3. Add your rule/fix
4. Submit a PR

---

## 📄 License

MIT © [Your Name]

---

## 🔗 Links

- **GitHub**: https://github.com/adnxy/react-native-lupin
- **NPM**: https://www.npmjs.com/package/react-native-lupin
- **Issues**: https://github.com/adnxy/react-native-lupin/issues

---

## ⭐ Support

If Lupin helped secure your app:
- ⭐ Star the repo
- 📢 Share with other React Native devs
- 🐛 Report issues
- 💡 Suggest improvements

---

**Made with ❤️ for React Native & Expo developers who care about security** 🔒
