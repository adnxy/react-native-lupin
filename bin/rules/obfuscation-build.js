/**
 * Obfuscation & Code Protection and Build Security Rules
 */
import { makeFinding, isBundleMinified } from '../utils/scan-helpers.js';

export const OBFUSCATION_BUILD_RULES = [
  // Minification/Obfuscation checks
  {
    id: 'OBF-001',
    title: 'Unminified production bundle',
    severity: 'medium',
    run: (code) => {
      // Check if bundle appears to be unminified
      if (!isBundleMinified(code)) {
        return [makeFinding('Bundle appears unminified. Production bundles should be minified for security and performance.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'OBF-002',
    title: 'Source map in production',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /\/\/[@#]\s*sourceMappingURL=/g,
        /\/\*[@#]\s*sourceMappingURL=/g,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Source map reference in production bundle. Remove source maps from production builds.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'OBF-003',
    title: 'Readable function/variable names',
    severity: 'low',
    run: (code) => {
      // Sample the code for readable naming patterns
      const sample = code.slice(0, 50000);
      const readablePatterns = [
        /function\s+(?:handleLogin|handleSubmit|validatePassword|authenticate|authorize)/gi,
        /const\s+(?:privateKey|secretKey|apiToken|authToken)\s*=/gi,
      ];
      
      const results = [];
      for (const rx of readablePatterns) {
        let m;
        let count = 0;
        while ((m = rx.exec(sample)) && count < 3) {
          results.push(makeFinding('Readable sensitive function/variable names detected. Consider obfuscation for production.', m.index, code, m[0]));
          count++;
        }
      }
      return results;
    },
  },

  // ProGuard/R8 configuration indicators
  {
    id: 'OBF-004',
    title: 'Missing ProGuard/R8 obfuscation indicators',
    severity: 'medium',
    run: (code) => {
      // Check for patterns that suggest ProGuard/R8 was NOT applied
      const hasProguardApplied = /[a-z]\.[a-z]\.[a-z]\(/g.test(code.slice(0, 10000));
      
      if (!hasProguardApplied && /android/i.test(code)) {
        return [makeFinding('Bundle may not have ProGuard/R8 obfuscation. Ensure ProGuard is enabled for Android release builds.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'OBF-005',
    title: 'Debug symbols in production',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /\.debug\s*=\s*true/gi,
        /DEBUG\s*=\s*true/g,
        /debugInfo\s*:/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Debug symbols or flags in production bundle. Strip debug info from release builds.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Build security - signing keys
  {
    id: 'BUILD-001',
    title: 'Signing key or keystore reference',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:keystore|key\.store|release\.keystore)/gi,
        /(?:KEYSTORE_PASSWORD|KEY_PASSWORD|SIGNING_KEY)/gi,
        /storePassword\s*[:=]/gi,
        /keyPassword\s*[:=]/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Signing key or keystore reference in bundle. CRITICAL: Never expose signing keys.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'BUILD-002',
    title: 'CI/CD credentials or tokens',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:GITHUB_TOKEN|GITLAB_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN)/gi,
        /(?:CI_TOKEN|BUILD_TOKEN|DEPLOY_TOKEN)/gi,
        /(?:JENKINS|TEAMCITY|BAMBOO).*(?:password|token)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('CI/CD credentials detected in bundle. Remove build system tokens from client code.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'BUILD-003',
    title: 'Build script references',
    severity: 'low',
    run: (code) => {
      const results = [];
      const patterns = [
        /gradle\.properties/gi,
        /build\.gradle/gi,
        /fastlane/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        let count = 0;
        while ((m = rx.exec(code)) && count < 2) {
          results.push(makeFinding('Build script reference in bundle. Verify no sensitive build configuration leaked.', m.index, code, m[0]));
          count++;
        }
      }
      return results;
    },
  },

  {
    id: 'BUILD-004',
    title: 'Apple certificates or provisioning profiles',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /\.p12|\.cer|\.mobileprovision/gi,
        /(?:CERT_PASSWORD|P12_PASSWORD|PROVISIONING)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Apple certificate or provisioning reference. Never expose signing certificates.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Hermes bytecode
  {
    id: 'OBF-006',
    title: 'Hermes bytecode detection',
    severity: 'info',
    run: (code) => {
      if (/HermesInternal/.test(code)) {
        return [makeFinding('Hermes engine detected. Hermes provides some native code protection but consider additional obfuscation.', 0, code)];
      }
      return [];
    },
  },

  // String encryption
  {
    id: 'OBF-007',
    title: 'Unencrypted sensitive strings',
    severity: 'medium',
    run: (code) => {
      // Check for plain sensitive strings without any obfuscation attempts
      const sensitiveStrings = [
        /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO)/gi,
        /["'](?:admin|root|superuser)["']/gi,
      ];
      
      const results = [];
      for (const rx of sensitiveStrings) {
        let m;
        let count = 0;
        while ((m = rx.exec(code)) && count < 3) {
          results.push(makeFinding('Sensitive string literals in plain text. Consider string encryption for production.', m.index, code, m[0]));
          count++;
        }
      }
      return results;
    },
  },

  // React DevTools
  {
    id: 'OBF-008',
    title: 'React DevTools enabled',
    severity: 'medium',
    run: (code) => {
      if (/__REACT_DEVTOOLS_GLOBAL_HOOK__/.test(code) && !/__DEV__\s*&&/.test(code)) {
        return [makeFinding('React DevTools may be enabled in production. Disable DevTools for release builds.', 0, code)];
      }
      return [];
    },
  },

  // Redux DevTools
  {
    id: 'OBF-009',
    title: 'Redux DevTools enabled',
    severity: 'medium',
    run: (code) => {
      if (/redux-devtools|__REDUX_DEVTOOLS_EXTENSION__/.test(code) && !/__DEV__/.test(code)) {
        return [makeFinding('Redux DevTools may be enabled in production. Disable for release builds.', 0, code)];
      }
      return [];
    },
  },

  // Console statements
  {
    id: 'OBF-010',
    title: 'Excessive console statements',
    severity: 'low',
    run: (code) => {
      // Count console statements
      const consoleCount = (code.match(/console\.(log|warn|error|info|debug)/g) || []).length;
      
      if (consoleCount > 50) {
        return [makeFinding(`${consoleCount} console statements detected. Remove debug logs from production builds.`, 0, code)];
      }
      return [];
    },
  },
];

