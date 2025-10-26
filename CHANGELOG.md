# Changelog

All notable changes to Lupin Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2025-10-26

### 🎉 Initial Release

First public release of Lupin Security Scanner!

### Added

#### Core Features
- ✅ CLI tool for scanning React Native and Expo bundles
- ✅ Auto-detection of project type (Expo vs React Native CLI)
- ✅ Automatic bundle discovery in common locations
- ✅ Interactive bundle selection
- ✅ Beautiful colored console output with progress bars
- ✅ Real-time scanning with visual feedback
- ✅ JSON report export for CI/CD integration

#### Security Rules (60+ total)
- 🤖 **AI Services (12 rules)**: OpenAI, Claude, Gemini, Cohere, Hugging Face, Azure OpenAI, Replicate, AI21, Stability AI, Mistral AI
- 🔑 **API Keys & Secrets (15 rules)**: Stripe, AWS, GitHub, Firebase, Mapbox, Twilio, SendGrid, Algolia, Sentry, Slack
- 📱 **Mobile Security (18 rules)**: AsyncStorage, database encryption, biometrics, deep linking, clipboard, WebView, SSL/TLS
- 💳 **PCI-DSS (5 rules)**: Credit card numbers, CVV, PIN codes, SSN
- 🔓 **Code Security (10 rules)**: eval(), Function(), console logging, debug code, admin patterns
- 🌐 **Network Security (5 rules)**: HTTP URLs, SSL verification, certificate pinning

#### Command Line Options
- `--bundle <path>` - Scan specific bundle
- `--type <type>` - Project type (expo/rn-cli)
- `--json <file>` - Export JSON report
- `--show-level <level>` - Filter displayed findings
- `--fail-level <level>` - Exit code threshold
- `--scan-all` - Non-interactive mode
- `--max-findings <n>` - Limit results
- `--no-color` - Disable colors

#### Documentation
- 📖 Complete README with examples
- 🚀 Quick Start guide
- 🔄 CI/CD integration guide (GitHub Actions, GitLab CI, Expo EAS)
- 📦 Publishing guide for maintainers

### Security Coverage

**Critical Severity (15 patterns):**
- API keys for AI services and payment processors
- Private keys (RSA, PEM)
- Database credentials
- OAuth secrets
- Admin credentials

**High Severity (18 patterns):**
- eval() and Function() usage
- Sensitive data in AsyncStorage
- JWT tokens in code
- Unencrypted databases
- SSL/TLS disabled
- Authentication bypass patterns

**Medium Severity (15 patterns):**
- Console logging of secrets
- HTTP URLs (should be HTTPS)
- Clipboard security issues
- Debug code in production
- WebView security misconfigurations

**Low Severity (7 patterns):**
- Hardcoded API endpoints
- Development markers
- Missing security features

### Performance
- ⚡ Scans 3MB bundles in ~2-3 seconds
- 🔍 Shannon entropy for secret detection
- ♻️ Automatic deduplication of findings
- 📊 Progress bars for real-time feedback

### Compatibility
- ✅ Node.js 16+
- ✅ Expo SDK 45+
- ✅ React Native 0.60+
- ✅ macOS, Linux, Windows
- ✅ GitHub Actions, GitLab CI, CircleCI, Bitrise
- ✅ EAS Build hooks

---

## [Unreleased]

### Planned for v1.1.0
- [ ] Source map support for better error locations
- [ ] Custom rule definitions
- [ ] Configuration file support (.lupinrc)
- [ ] HTML report generation
- [ ] IDE extensions (VS Code, IntelliJ)

### Planned for v2.0.0
- [ ] Programmatic Node.js API
- [ ] Plugin system
- [ ] Real-time file watching
- [ ] Git diff scanning (only changed code)
- [ ] SARIF format export
- [ ] Integration with security dashboards

---

## Contributing

Found a bug or want to suggest a feature? [Open an issue](https://github.com/adnxy/react-native-lupin/issues)!

---

[1.0.0]: https://github.com/adnxy/react-native-lupin/releases/tag/v1.0.0
