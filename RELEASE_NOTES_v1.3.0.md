# 🔒 Lupin v1.3.0 - Modular Architecture Release

## 🚀 Major Improvements

### Modular Architecture
This release introduces a **complete code refactoring** with a clean, modular architecture:

- **Main scanner reduced from 1,529 to 633 lines** (-60% code!)
- **7 specialized rule modules** (2,546 lines total):
  - `core-rules.js` (893 lines) - Original security checks
  - `dependency-security.js` (167 lines) - Dependency & supply chain
  - `file-storage-security.js` (190 lines) - File & storage security
  - `permissions-privacy.js` (244 lines) - Permissions & privacy  
  - `obfuscation-build.js` (277 lines) - Build & obfuscation
  - `auth-session.js` (312 lines) - Authentication & sessions
  - `react-native-specific.js` (463 lines) - React Native specific checks
- **Utility helpers** extracted to `scan-helpers.js` (110 lines)

### 127 Security Rules (77+ New!)

#### 🔗 Dependency & Supply Chain Security
- Deprecated React Native modules (AsyncStorage, NetInfo, WebView, ListView, Geolocation, CameraRoll, Clipboard)
- Known vulnerable packages (lodash, event-stream, flatmap-stream)
- Outdated React Native API patterns
- PropTypes deprecation warnings

#### 📁 File and Storage Security
- Unencrypted sensitive file patterns
- Android external storage usage detection
- Insecure file permissions
- iOS file protection checks
- Hardcoded resource file paths
- Unverified file downloads
- Cache directory security
- SharedPreferences/UserDefaults risks
- Android backup flags
- Temporary file security

#### 🔐 Permissions and Privacy (15+ checks)
- Camera, microphone, location permissions
- Contacts, calendar, SMS, call log access
- Storage permissions (scoped storage)
- Device ID/IDFA/GAID collection
- Biometric data collection
- Health data access
- Clipboard tracking
- Background location tracking
- Screenshot prevention
- Bluetooth and network state
- Photo library access

#### 🛡️ Obfuscation & Build Security
- Unminified production bundle detection
- Source maps in production
- Readable function/variable names
- Missing ProGuard/R8 configuration
- Debug symbols in production
- Exposed signing keys/keystores
- CI/CD credentials detection
- Build script references
- Apple certificates/provisioning
- Hermes bytecode validation
- React/Redux DevTools detection
- Excessive console statements

#### 🔑 Authentication & Session Security (20+ checks)
- JWT/tokens in AsyncStorage
- Missing SecureStore usage
- Token expiration validation
- Long-lived token detection
- Refresh token mechanisms
- OAuth without PKCE
- OAuth redirect URI validation
- Missing state parameters
- Session timeout checks
- Hardcoded session IDs
- API keys in headers/URLs
- Password validation
- Weak password requirements
- Biometric fallback security
- Missing 2FA/MFA
- Insecure "Remember Me"
- Certificate pinning for auth
- Social login token validation
- Account enumeration risks

#### ⚛️ React Native Specific (30+ checks)
- Dynamic code execution (eval, Function, require/import)
- Missing root/jailbreak detection
- App integrity/tampering checks
- WebView security (JavaScript, injectedJavaScript, file access)
- WebView origin whitelist
- WebView message validation
- Native module input validation
- Deep link validation
- Remote debugging enabled
- Dev menu accessible
- Performance monitor
- Debug server URLs
- Network request logging
- Reanimated worklet security
- AsyncStorage encryption
- SQLite/Realm without encryption
- Expo OTA update security
- Development mode indicators
- Ad SDK excessive permissions
- Analytics SDK data collection
- Crash reporting sensitive data
- CodePush signature verification
- Sensitive actions on gestures

## 🎨 Enhanced User Experience

- **Cleaner console output** - Only HIGH/CRITICAL findings shown during scan
- **Smart summaries** - Medium/low findings displayed as compact counts
- **Full JSON reports** - All findings (including hidden ones) saved to JSON
- **Better progress display** - Visual feedback with gradient progress bars
- **Improved logging** - Medium warnings show count, full details in reports

## 📊 Production Tested

✅ **Tested on real projects:**
- Expo app with 2.9MB production bundle
- React Native 0.81.5 with Hermes
- Detected 8,233 findings (1 critical, 12 high, 8,220 medium)
- Auto-discovery working perfectly

## 🔧 Technical Improvements

- Better code organization and maintainability
- Easier to extend with new security rules
- Improved performance with modular loading
- Cleaner separation of concerns
- Enhanced error handling
- Better regex pattern matching
- Improved entropy detection accuracy

## 📦 Installation

```bash
npm install -g react-native-lupin
```

or

```bash
npx react-native-lupin
```

## 🚦 Quick Start

```bash
# Auto-detect and scan
lupin

# Scan specific bundle
lupin --bundle path/to/main.jsbundle

# Expo project
lupin --type expo --scan-all

# CI/CD integration
lupin --fail-level high --show-level high
```

## 📝 Breaking Changes

None - fully backward compatible with v1.2.0

## 🐛 Bug Fixes

- Fixed duplicate rule execution
- Improved entropy detection accuracy
- Better handling of minified code
- Enhanced regex pattern matching

## 🙏 Feedback

Found a bug or have a feature request? Open an issue on [GitHub](https://github.com/adnxy/react-native-lupin/issues)!

---

**Full Changelog**: https://github.com/adnxy/react-native-lupin/compare/v1.2.0...v1.3.0


