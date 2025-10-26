/**
 * React Native Specific Security Rules
 */
import { findRegex, makeFinding } from '../utils/scan-helpers.js';

export const REACT_NATIVE_RULES = [
  // Dynamic code execution
  {
    id: 'RN-EXEC-001',
    title: 'Dynamic code execution with eval',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /\beval\s*\(/g,
      'eval() enables arbitrary code execution. Extremely dangerous - remove immediately.'
    ),
  },

  {
    id: 'RN-EXEC-002',
    title: 'Function constructor usage',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /\bnew\s+Function\s*\(/g,
      'Function constructor can execute arbitrary code. Remove or sanitize inputs strictly.'
    ),
  },

  {
    id: 'RN-EXEC-003',
    title: 'Dynamic require/import',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /require\s*\(\s*[a-z_$][\w$]*\s*\)/gi,  // require(variable)
        /import\s*\(\s*[a-z_$][\w$]*\s*\)/gi,   // import(variable)
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Dynamic require/import with variables. Can lead to code injection if user-controlled.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Root/Jailbreak detection
  {
    id: 'RN-INTEGRITY-001',
    title: 'Missing root/jailbreak detection',
    severity: 'medium',
    run: (code) => {
      const hasSensitiveOps = /(?:SecureStore|Keychain|biometric|payment|banking)/gi.test(code);
      const hasRootDetection = /JailMonkey|RootBeer|jailbreak|rooted|isJailBroken|isRooted/gi.test(code);
      
      if (hasSensitiveOps && !hasRootDetection) {
        return [makeFinding('Sensitive operations without root/jailbreak detection. Consider implementing device integrity checks.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'RN-INTEGRITY-002',
    title: 'App integrity/tampering detection',
    severity: 'medium',
    run: (code) => {
      const hasAuth = /authenticate|login|token|payment/gi.test(code);
      const hasTamperDetection = /tamper|integrity.*check|signature.*verif/gi.test(code);
      
      if (hasAuth && !hasTamperDetection) {
        return [makeFinding('No app integrity/tampering detection found. Consider implementing to prevent modified apps.', 0, code)];
      }
      return [];
    },
  },

  // WebView security
  {
    id: 'RN-WV-001',
    title: 'WebView with JavaScript enabled',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /javaScriptEnabled\s*[:=]\s*true/gi,
      'WebView with JavaScript enabled. Only enable for trusted content and sanitize all data passed to WebView.'
    ),
  },

  {
    id: 'RN-WV-002',
    title: 'WebView injectedJavaScript',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /injectedJavaScript\s*[:=]/gi,
      'WebView injectedJavaScript detected. Sanitize all injected code to prevent XSS vulnerabilities.'
    ),
  },

  {
    id: 'RN-WV-003',
    title: 'WebView file access enabled',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /allowFileAccess\s*[:=]\s*true/gi,
        /allowUniversalAccessFromFileURLs\s*[:=]\s*true/gi,
        /allowFileAccessFromFileURLs\s*[:=]\s*true/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('WebView file access enabled. Can expose local files. Disable unless absolutely necessary.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'RN-WV-004',
    title: 'WebView origin whitelist too broad',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /originWhitelist\s*[:=]\s*\[\s*['"]?\*['"]?\s*\]/gi,
      'WebView originWhitelist set to "*". Restrict to specific trusted domains only.'
    ),
  },

  {
    id: 'RN-WV-005',
    title: 'WebView message handling without validation',
    severity: 'critical',
    run: (code) => {
      const results = [];
      // Check for onMessage without validation
      const onMessagePattern = /onMessage\s*[:=]\s*\{?\s*\(?\s*(?:event|e|message)\s*\)?\s*=>/gi;
      let m;
      while ((m = onMessagePattern.exec(code))) {
        const snippet = code.slice(m.index, m.index + 200);
        // Check if validation exists nearby
        if (!/validate|sanitize|check|verify|whitelist/.test(snippet)) {
          results.push(makeFinding('WebView onMessage without input validation. Always validate and sanitize messages from WebView.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'RN-WV-006',
    title: 'WebView postMessage with sensitive data',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /postMessage\s*\([^)]*(?:password|token|secret|key|pin)/gi,
      'Posting sensitive data to WebView. WebView communication can be intercepted.'
    ),
  },

  // Native module bridges
  {
    id: 'RN-BRIDGE-001',
    title: 'Native module without input validation',
    severity: 'high',
    run: (code) => {
      const results = [];
      // Look for NativeModules usage
      const bridgePattern = /NativeModules\.[a-zA-Z]+\.[a-zA-Z]+\s*\(/gi;
      let m;
      while ((m = bridgePattern.exec(code))) {
        const snippet = code.slice(Math.max(0, m.index - 100), m.index + 100);
        // Check if input validation exists
        if (!/validate|sanitize|check.*input/.test(snippet)) {
          results.push(makeFinding('Native module call without input validation. Validate all data passed to native code.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Deep linking
  {
    id: 'RN-LINK-001',
    title: 'Deep link without validation',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /Linking\.getInitialURL/gi,
        /Linking\.addEventListener/gi,
        /useURL\s*\(/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          const snippet = code.slice(m.index, m.index + 300);
          // Check if validation exists
          if (!/validate|sanitize|whitelist|check/.test(snippet)) {
            results.push(makeFinding('Deep link handling without validation. Always validate and sanitize deep link URLs.', m.index, code, m[0]));
          }
        }
      }
      return results;
    },
  },

  {
    id: 'RN-LINK-002',
    title: 'Deep link with eval or navigation',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /Linking\..*\.then.*(?:eval|navigate|redirect|window\.location)/gi,
      'Deep link directly triggering navigation/eval. Extremely dangerous - validate and whitelist URLs.'
    ),
  },

  // Debugging and development
  {
    id: 'RN-DEBUG-001',
    title: 'Remote debugging enabled',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /connectToDevTools|__DEV__\s*\|\|\s*true|debugger.*enabled/gi,
      'Remote debugging may be enabled in production. Disable all debugging in release builds.'
    ),
  },

  {
    id: 'RN-DEBUG-002',
    title: 'Dev menu accessible',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /DevMenu|DeveloperMenu|showDevMenu/gi,
      'Developer menu may be accessible. Ensure dev menu is disabled in production.'
    ),
  },

  {
    id: 'RN-DEBUG-003',
    title: 'Performance monitor enabled',
    severity: 'low',
    run: (code) => findRegex(
      code,
      /showFPS|showPerfMonitor|performanceMonitor.*true/gi,
      'Performance monitor enabled. Disable for production builds.'
    ),
  },

  {
    id: 'RN-DEBUG-004',
    title: 'Debug server URLs',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /localhost:\d{4}|127\.0\.0\.1:\d{4}|0\.0\.0\.0:\d{4}/g,
      'Debug server URL detected. Remove localhost references from production builds.'
    ),
  },

  // Network debugging
  {
    id: 'RN-DEBUG-005',
    title: 'Network request logging',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /XMLHttpRequest.*addEventListener.*console/gi,
        /fetch.*\.then.*console\.log/gi,
        /axios.*interceptor.*console/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Network request logging detected. May expose sensitive data in logs.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Reanimated worklet security
  {
    id: 'RN-REANIMATE-001',
    title: 'Reanimated worklet with user input',
    severity: 'medium',
    run: (code) => {
      const results = [];
      if (/worklet|useAnimatedStyle|useSharedValue/.test(code)) {
        const workletPattern = /worklet[^}]{0,200}(?:props|input|data|value)/gi;
        let m;
        while ((m = workletPattern.exec(code))) {
          results.push(makeFinding('Reanimated worklet using external data. Validate inputs as worklets run on UI thread.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // AsyncStorage security
  {
    id: 'RN-STORAGE-001',
    title: 'AsyncStorage for sensitive data',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /AsyncStorage\.setItem\s*\([^)]*(?:password|token|secret|key|pin|ssn|credit)/gi,
      'Storing sensitive data in AsyncStorage. Use SecureStore/Keychain for sensitive information.'
    ),
  },

  {
    id: 'RN-STORAGE-002',
    title: 'SQLite without encryption',
    severity: 'medium',
    run: (code) => {
      const hasSQLite = /SQLite|openDatabase|executeSql/gi.test(code);
      const hasEncryption = /SQLCipher|encryption|encryptionKey/gi.test(code);
      
      if (hasSQLite && !hasEncryption) {
        return [makeFinding('SQLite database without encryption. Use SQLCipher for sensitive data.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'RN-STORAGE-003',
    title: 'Realm without encryption',
    severity: 'high',
    run: (code) => {
      const results = [];
      const realmPattern = /new\s+Realm\s*\([^)]*\)/g;
      let m;
      while ((m = realmPattern.exec(code))) {
        const realmConfig = m[0];
        if (!/encryptionKey/.test(realmConfig)) {
          results.push(makeFinding('Realm database without encryption. Always use encryptionKey for sensitive data.', m.index, code, realmConfig));
        }
      }
      return results;
    },
  },

  // Expo specific
  {
    id: 'RN-EXPO-001',
    title: 'Expo OTA updates without code signing',
    severity: 'medium',
    run: (code) => {
      const hasExpoUpdates = /expo-updates|Updates\.checkForUpdate/gi.test(code);
      const hasCodeSigning = /codeSigningCertificate|privateKey.*update/gi.test(code);
      
      if (hasExpoUpdates && !hasCodeSigning) {
        return [makeFinding('Expo OTA updates without code signing verification. Enable code signing for production updates.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'RN-EXPO-002',
    title: 'Expo development mode indicators',
    severity: 'low',
    run: (code) => findRegex(
      code,
      /Constants\.manifest\..*(?:dev|development)|__DEV__.*expo/gi,
      'Expo development mode indicators present. Ensure stripped from production.'
    ),
  },

  // Third-party SDK security
  {
    id: 'RN-SDK-001',
    title: 'Ad SDK with excessive permissions',
    severity: 'medium',
    run: (code) => {
      const hasAdSDK = /AdMob|FacebookAds|UnityAds|AppLovin/gi.test(code);
      const hasLocationAccess = /location|gps|coordinates/gi.test(code);
      
      if (hasAdSDK && hasLocationAccess) {
        return [makeFinding('Ad SDK with location access. Review if ads need location data - privacy concern.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'RN-SDK-002',
    title: 'Analytics SDK collecting sensitive data',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:analytics|track|log.*event)\s*\([^)]*(?:password|pin|ssn|credit.*card)/gi,
        /(?:Mixpanel|Amplitude|Segment).*track.*(?:email|phone|address)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Analytics tracking potentially sensitive data. Never send PII/sensitive data to analytics.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'RN-SDK-003',
    title: 'Crash reporting with sensitive data',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:Sentry|Crashlytics|Bugsnag).*(?:setUser|setContext).*(?:password|token|key)/gi,
      'Crash reporting with sensitive data. Sanitize crash reports before sending.'
    ),
  },

  // CodePush security
  {
    id: 'RN-CODEPUSH-001',
    title: 'CodePush without signature verification',
    severity: 'high',
    run: (code) => {
      const hasCodePush = /CodePush|codePush\.sync/gi.test(code);
      const hasSignatureCheck = /publicKey|signature.*verif/gi.test(code);
      
      if (hasCodePush && !hasSignatureCheck) {
        return [makeFinding('CodePush without signature verification. Enable code signing for CodePush updates.', 0, code)];
      }
      return [];
    },
  },

  // Gesture handling
  {
    id: 'RN-GESTURE-001',
    title: 'Sensitive actions on simple gesture',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /onPress.*(?:delete|remove|transfer|send.*payment|confirm.*purchase)/gi,
      'Critical action on simple tap. Consider confirmation dialogs for destructive/financial actions.'
    ),
  },
];

