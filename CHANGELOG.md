# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-26

### 🎉 Initial Release

#### Added
- **Core Scanner Engine**
  - Static analysis of React Native and Expo JavaScript bundles
  - 60+ security detection rules across multiple categories
  - Shannon entropy analysis for unknown secret detection
  - Real-time progress display with severity alerts

- **API Key Detection (25+ providers)**
  - OpenAI (GPT-4, GPT-3.5, organization keys)
  - Anthropic (Claude)
  - Google AI (Gemini, PaLM, Vertex AI)
  - AWS Access Keys
  - Stripe (Secret and Restricted keys)
  - Twilio Account SID and Auth Tokens
  - SendGrid API Keys
  - Firebase API Keys
  - OAuth Client Secrets
  - GitHub Personal Access Tokens
  - Hugging Face Tokens
  - Replicate API Tokens
  - AI21 Labs Keys
  - Mistral AI Keys
  - Stability AI Keys
  - And 10+ more providers

- **React Native Security Checks**
  - AsyncStorage sensitive data detection
  - Redux/State management security
  - Unencrypted Realm database detection
  - SQLite encryption checks
  - WebView security (XSS, injection, JavaScript bridge)
  - Deep linking vulnerability detection
  - Biometric authentication bypass risks
  - SSL/TLS verification bypass detection
  - Certificate pinning checks
  - Clipboard sensitive data exposure
  - Debug mode detection in production

- **Critical Vulnerability Detection**
  - Hardcoded admin credentials
  - Private key (RSA, ECDSA) exposure
  - Database connection strings with credentials
  - Payment card data handling
  - Hardcoded encryption keys
  - JWT token detection

- **Code Execution Risks**
  - eval() usage detection
  - Function constructor usage
  - Unsafe deep link handling
  - WebView JavaScript bridge security

- **CLI Features**
  - Auto-detection of Expo and React Native CLI projects
  - Automatic bundle discovery
  - Interactive bundle selection
  - Multiple bundle scanning
  - Real-time progress bar and detection alerts
  - Beautiful formatted console output with colors
  - Configurable severity display levels
  - Configurable fail levels for CI/CD
  - JSON report export
  - Source map detection

- **Programmatic API**
  - `scanBundle()` - Scan single bundles
  - `scanMultipleBundles()` - Scan multiple bundles
  - `detectProjectType()` - Auto-detect project type
  - `findBundles()` - Auto-discover bundle files
  - Full TypeScript type definitions (JSDoc)

- **CI/CD Integration**
  - Exit codes for pipeline integration
  - JSON report format
  - Configurable fail thresholds
  - No-color mode for CI environments
  - Example workflows for:
    - GitHub Actions
    - GitLab CI
    - CircleCI
    - Jenkins

- **Documentation**
  - Comprehensive README with examples
  - API documentation
  - Testing guide
  - Contributing guidelines
  - Security policy
  - CI/CD integration examples

### Security Rules by Category

#### API Keys & Secrets (25 rules)
- `KEY-OPENAI` - OpenAI API Keys
- `KEY-OPENAI-PROJ` - OpenAI Project Keys
- `KEY-OPENAI-ORG` - OpenAI Organization Keys
- `KEY-ANTHROPIC` - Anthropic (Claude) Keys
- `KEY-GOOGLE-AI` - Google AI/Gemini Keys
- `KEY-STRIPE` - Stripe Secret Keys
- `KEY-AWS` - AWS Access Keys
- `KEY-GCP` - Google Cloud API Keys
- `KEY-FIREBASE` - Firebase API Keys
- `KEY-TWILIO` - Twilio Credentials
- `KEY-SENDGRID` - SendGrid API Keys
- `KEY-SLACK` - Slack Tokens
- `KEY-GH` - GitHub Tokens
- `KEY-FACEBOOK` - Facebook App Secrets
- `KEY-TWITTER` - Twitter API Secrets
- `KEY-MAPBOX` - Mapbox Tokens
- `KEY-ALGOLIA` - Algolia Keys
- `KEY-OAUTH` - OAuth Client Secrets
- `KEY-HUGGINGFACE` - Hugging Face Tokens
- `KEY-AZURE-OPENAI` - Azure OpenAI Keys
- `KEY-REPLICATE` - Replicate Tokens
- `KEY-AI21` - AI21 Labs Keys
- `KEY-MISTRAL` - Mistral AI Keys
- `KEY-STABILITY` - Stability AI Keys
- `KEY-OTHER` - High-entropy string detection

#### React Native Security (18 rules)
- `RN-001` - eval() usage
- `RN-002` - Function constructor
- `RN-ASYNC-001` - Sensitive data in AsyncStorage
- `RN-STATE-001` - Sensitive data in Redux/State
- `RN-DB-001` - Unencrypted Realm database
- `RN-DB-002` - SQLite encryption check
- `RN-LOG-001` - Logging sensitive data
- `RN-AUTH-001` - Biometric bypass risk
- `RN-LINK-001` - Unsafe deep link handling
- `RN-NET-002` - Certificate pinning not detected
- `RN-NET-003` - Insecure SSL/TLS configuration
- `RN-CLIP-001` - Sensitive data in clipboard
- `RN-DEBUG-001` - Debug mode enabled
- `RN-SCHEME-001` - Custom URL scheme security
- `WV-001` - Potential unsafe WebView usage
- `WV-002` - WebView JavaScript bridge
- `NET-001` - Insecure HTTP URLs
- `EXPO-001` - Expo SecureStore usage check

#### Critical Vulnerabilities (10 rules)
- `KEY-PRIVATE` - Private key detection
- `ADMIN-001` - Hardcoded admin credentials
- `DB-URL-001` - Database connection strings
- `PAY-001` - Payment card data handling
- `CRYPTO-001` - Hardcoded encryption keys
- `JWT-001` - JWT token detection
- `ENV-002` - Environment secrets in bundle
- `KEY-PUSH` - Push notification secrets
- `KEY-ANALYTICS` - Analytics write keys
- `KEY-SDK` - Third-party SDK keys

#### Debug & Configuration (7 rules)
- `DBG-001` - Development markers leaked
- `ENV-001` - Staging/test endpoints
- `API-001` - Hardcoded API endpoints
- `KEY-AI-GENERIC` - Generic AI API key patterns
- `KEY-COHERE` - Cohere API keys
- `KEY-SENTRY` - Sentry DSN

### Technical Details

- **Language**: JavaScript (ES Modules)
- **Runtime**: Node.js ≥16.0.0
- **Dependencies**: 
  - commander (CLI parsing)
  - chalk (colored output)
  - glob (file discovery)
- **Package Size**: ~150KB (unpacked)
- **Performance**: Scans 1MB bundle in ~2-3 seconds

### Breaking Changes
- None (initial release)

### Migration Guide
- None (initial release)

---

## [Unreleased]

### Planned Features
- Source map support for accurate line numbers
- Custom rule configuration files
- Rule severity customization
- Ignore patterns / whitelisting
- HTML report generation
- SARIF format export
- IDE extensions (VSCode, WebStorm)
- Pre-commit hook automation
- Docker image
- Web dashboard for report viewing

---

## Release Notes Format

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security vulnerability fixes

---

[1.0.0]: https://github.com/yourusername/lupin-security-scanner/releases/tag/v1.0.0
[Unreleased]: https://github.com/yourusername/lupin-security-scanner/compare/v1.0.0...HEAD

