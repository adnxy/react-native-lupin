/**
 * Core Security Rules (Original/Existing Rules)
 * These are the original rules from the scanner
 */
import { 
  findRegex, 
  makeFinding, 
  shannonEntropy, 
  maybeBase64ish, 
  maybeHexish, 
  slicePreview 
} from '../utils/scan-helpers.js';

export const CORE_RULES = [
  // Dangerous dynamic code execution
  {
    id: 'RN-001',
    title: 'Use of eval',
    severity: 'high',
    run: (code) => findRegex(code, /\beval\s*\(/g, 'Use of eval() can lead to code injection.'),
  },
  {
    id: 'RN-002',
    title: 'Use of Function constructor',
    severity: 'high',
    run: (code) => findRegex(code, /\bnew\s+Function\s*\(/g, 'Use of new Function() can lead to code injection.'),
  },

  // Insecure network usage
  {
    id: 'NET-001',
    title: 'Insecure HTTP URLs',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const regex = /http:\/\/(?!localhost|127\.0\.0\.1)[^\s"'`);]+/g;
      let m;
      while ((m = regex.exec(code))) {
        results.push(makeFinding('Use HTTPS instead of HTTP for production endpoints.', m.index, code, m[0]));
      }
      return results;
    },
  },

  // Hard-coded tokens / keys (heuristics + known formats)
  // Known providers
  {
    id: 'KEY-STRIPE',
    title: 'Stripe Secret Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:sk_live|rk_live)_[A-Za-z0-9]{10,}/g,
      'Stripe secret key detected. Never ship secrets in client bundles.'
    ),
  },
  {
    id: 'KEY-GCP',
    title: 'Google API Key',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /AIza[0-9A-Za-z\-_]{35}/g,
      'Google API key detected. Consider restricting by domain/HTTP referrer or server-only.'
    ),
  },
  {
    id: 'KEY-SENTRY',
    title: 'Sentry DSN',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /https?:\/\/[A-Za-z0-9]+@[A-Za-z0-9\.\-]+\/\d+/g,
      'Sentry DSN detected. Ensure it is public-safe or use server-side upload for source maps.'
    ),
  },
  {
    id: 'KEY-SLACK',
    title: 'Slack Token',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /xox[baprs]-[A-Za-z0-9-]{10,}/g,
      'Possible Slack token detected.'
    ),
  },
  {
    id: 'KEY-AWS',
    title: 'AWS Access Key',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /AKIA[0-9A-Z]{16}/g,
      'Possible AWS Access Key ID detected.'
    ),
  },
  {
    id: 'KEY-GH',
    title: 'GitHub Token',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}/g,
      'Possible GitHub token detected.'
    ),
  },
  {
    id: 'KEY-OTHER',
    title: 'High-entropy strings (likely secrets)',
    severity: 'medium',
    run: (code) => {
      // Scan quotes and bare tokens for secret-like strings
      const results = [];
      const stringish = /(?:"([^"\\]{12,})"|'([^'\\]{12,})'|`([^`\\]{12,})`)/g;
      let m;
      while ((m = stringish.exec(code))) {
        const value = m[1] || m[2] || m[3] || '';
        const cleaned = value.trim();

        // Skip obvious safe strings
        if (!cleaned) continue;
        if (/^[\w\-\.:/]+$/.test(cleaned) && cleaned.length < 24) continue;

        const ent = shannonEntropy(cleaned);
        const isLong = cleaned.length >= 20;
        const looksEncoded = maybeBase64ish(cleaned) || maybeHexish(cleaned);

        // Heuristic threshold: entropy >= 4.0 + looks encoded OR long
        if ((ent >= 4.0 && (looksEncoded || isLong)) || ent >= 4.5) {
          results.push({
            ...makeFinding(
              `High-entropy string detected (entropy=${ent.toFixed(2)}). Review for secrets.`,
              m.index,
              code,
              slicePreview(cleaned, 120)
            ),
            // Attach metadata
            meta: { entropy: ent, length: cleaned.length },
          });
        }
      }
      return results;
    },
  },

  // Environment / debug indicators in shipped bundle
  {
    id: 'DBG-001',
    title: 'Development markers leaked',
    severity: 'low',
    run: (code) => {
      const hits = [];
      for (const patt of [
        /__DEV__\s*=\s*true/g,
        /__REACT_DEVTOOLS_GLOBAL_HOOK__/g,
        /redux-devtools/g,
      ]) {
        let m;
        while ((m = patt.exec(code))) {
          hits.push(makeFinding('Development-only code references found. Ensure prod builds strip dev features.', m.index, code));
        }
      }
      return hits;
    },
  },

  // WebView risk hints in bundles that include UI code
  {
    id: 'WV-001',
    title: 'Potential unsafe WebView usage',
    severity: 'medium',
    run: (code) => {
      // We cannot parse JSX reliably in a minified bundle, but we can flag hints
      const results = [];
      const patterns = [
        { rx: /injectedJavaScript\s*:/g, msg: 'WebView injectedJavaScript present. Audit for XSS/injection risks.' },
        { rx: /javaScriptEnabled\s*:\s*true/g, msg: 'WebView javaScriptEnabled=true. Ensure content is trusted.' },
        { rx: /originWhitelist\s*:\s*\[\s*"\*"\s*\]/g, msg: 'WebView originWhitelist allows all. Restrict origins in production.' },
        { rx: /allowingReadAccessToURL/g, msg: 'WebView file URL access. Ensure paths are limited.' },
      ];
      for (const { rx, msg } of patterns) {
        let m;
        while ((m = rx.exec(code))) results.push(makeFinding(msg, m.index, code));
      }
      return results;
    },
  },

  // JWTs appearing in code (often a sign of hard-coded tokens)
  {
    id: 'JWT-001',
    title: 'JWT-like token found',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g,
      'JWT-like token present. Never bundle tokens in client code.'
    ),
  },

  // Staging/beta endpoints leaked
  {
    id: 'ENV-001',
    title: 'Staging/test endpoints in bundle',
    severity: 'low',
    run: (code) => {
      const rx = /\b(staging|sandbox|test|dev)\b[.\-_/][A-Za-z0-9.\-_/]+/gi;
      const results = [];
      let m;
      while ((m = rx.exec(code))) {
        results.push(makeFinding('Potential non-production endpoint reference present.', m.index, code, m[0]));
      }
      return results;
    },
  },

  // ========== React Native Specific Security ==========

  // AsyncStorage sensitive data storage
  {
    id: 'RN-ASYNC-001',
    title: 'Sensitive data in AsyncStorage',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /AsyncStorage\.setItem\s*\(\s*['"`].*?(password|token|secret|key|auth|credential).*?['"`]/gi,
        /setItem\s*\(\s*['"`].*?(password|token|secret|key|auth|credential).*?['"`]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Sensitive data stored in AsyncStorage. Use Keychain/SecureStore for sensitive data.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Redux/State Management sensitive data
  {
    id: 'RN-STATE-001',
    title: 'Sensitive data in Redux/State',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /password\s*:\s*action\.payload/gi,
        /creditCard\s*:\s*[^,}]+/gi,
        /cvv\s*:\s*[^,}]+/gi,
        /ssn\s*:\s*[^,}]+/gi,
        /(pin|pinCode)\s*:\s*[^,}]+/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Sensitive data in state management. Avoid storing passwords/PINs in Redux state.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // More API Keys and Tokens
  {
    id: 'KEY-FIREBASE',
    title: 'Firebase API Key',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:firebase[_-]?apiKey|FIREBASE[_-]?API[_-]?KEY)\s*[:=]\s*['"`]([A-Za-z0-9_\-]+)['"`]/gi,
      'Firebase API key detected. Ensure Firebase security rules are properly configured.'
    ),
  },

  {
    id: 'KEY-MAPBOX',
    title: 'Mapbox Token',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /pk\.[a-zA-Z0-9]{60,}/g,
      'Mapbox public token detected. Ensure token restrictions are in place.'
    ),
  },

  {
    id: 'KEY-TWILIO',
    title: 'Twilio Credentials',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /AC[a-z0-9]{32}|SK[a-z0-9]{32}/g,
      'Twilio Account SID or Auth Token detected. Never expose Twilio credentials in client code.'
    ),
  },

  {
    id: 'KEY-SENDGRID',
    title: 'SendGrid API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,
      'SendGrid API key detected. Remove immediately - this allows unauthorized email sending.'
    ),
  },

  {
    id: 'KEY-ALGOLIA',
    title: 'Algolia API Key',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /[a-z0-9]{32}(?=.*algolia)/gi,
      'Possible Algolia API key. Ensure you are using search-only key, not admin key.'
    ),
  },

  {
    id: 'KEY-OAUTH',
    title: 'OAuth Client Secret',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /client[_-]?secret\s*[:=]\s*['"`]([A-Za-z0-9_\-]{20,})['"`]/gi,
      'OAuth client secret detected. Client secrets must never be in mobile apps.'
    ),
  },

  {
    id: 'KEY-PRIVATE',
    title: 'Private Key Pattern',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/gi,
      'Private key detected in bundle. Remove immediately - this is a critical security breach.'
    ),
  },

  // Database and Storage
  {
    id: 'RN-DB-001',
    title: 'Unencrypted Realm Database',
    severity: 'high',
    run: (code) => {
      const results = [];
      // Look for Realm without encryption key
      const realmPattern = /new\s+Realm\s*\([^)]*\)/g;
      let m;
      while ((m = realmPattern.exec(code))) {
        const realmConfig = m[0];
        if (!/encryptionKey/.test(realmConfig)) {
          results.push(makeFinding('Realm database without encryption. Use encryptionKey for sensitive data.', m.index, code, realmConfig));
        }
      }
      return results;
    },
  },

  {
    id: 'RN-DB-002',
    title: 'SQLite encryption check',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /SQLite\.openDatabase\s*\([^)]*(?!.*key)[^)]*\)/gi,
      'SQLite database opened without encryption. Consider using SQLCipher for sensitive data.'
    ),
  },

  // Logging sensitive data
  {
    id: 'RN-LOG-001',
    title: 'Logging sensitive data',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /console\.log\s*\([^)]*(?:password|token|secret|key|auth|credential|pin|ssn|credit)/gi,
        /console\.warn\s*\([^)]*(?:password|token|secret|key|auth|credential)/gi,
        /console\.error\s*\([^)]*(?:password|token|secret|key|auth)/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Console logging may expose sensitive data. Remove or sanitize before production.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Biometric/Authentication
  {
    id: 'RN-AUTH-001',
    title: 'Biometric bypass risk',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /BiometricAuthentication|TouchID|FaceID.*(?:fallback|bypass|skip)/gi,
      'Biometric authentication with potential bypass. Ensure fallback is secure.'
    ),
  },

  // Deep linking vulnerabilities
  {
    id: 'RN-LINK-001',
    title: 'Unsafe deep link handling',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /Linking\.getInitialURL\s*\(\)\.then\s*\([^)]*\)\s*\.then\s*\([^)]*(?:eval|navigate|redirect)/gi,
        /scheme\s*[:=]\s*['"`](?:http|https)['"`]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Unsafe deep link handling. Validate and sanitize URLs before navigation.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Network security
  {
    id: 'RN-NET-002',
    title: 'Certificate pinning not detected',
    severity: 'low',
    run: (code) => {
      // Check if cert pinning is present for security-sensitive apps
      if (!/certificatePinning|pinnedCertificates|trustkit/gi.test(code) && 
          /fetch|axios|XMLHttpRequest/.test(code)) {
        return [makeFinding('No certificate pinning detected. Consider implementing for enhanced security.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'RN-NET-003',
    title: 'Insecure SSL/TLS configuration',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /rejectUnauthorized\s*:\s*false|SSL_VERIFY\s*=\s*false|allowInvalidCertificates/gi,
      'SSL/TLS verification disabled. This allows man-in-the-middle attacks.'
    ),
  },

  // Clipboard security
  {
    id: 'RN-CLIP-001',
    title: 'Sensitive data in clipboard',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /Clipboard\.setString\s*\([^)]*(?:password|token|secret|key|pin|otp)/gi,
      'Sensitive data copied to clipboard. Clipboard content can be accessed by other apps.'
    ),
  },

  // Debug mode checks
  {
    id: 'RN-DEBUG-001',
    title: 'Debug mode enabled',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /debugger;/g,
        /DEV\s*===?\s*true/g,
        /__DEV__\s*&&.*console/g,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Debug code present. Ensure debug features are disabled in production.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Expo specific
  {
    id: 'EXPO-001',
    title: 'Expo SecureStore usage check',
    severity: 'info',
    run: (code) => {
      // Check if AsyncStorage is used when SecureStore is available
      if (/AsyncStorage/.test(code) && /expo/.test(code) && 
          !/SecureStore/.test(code)) {
        return [makeFinding('AsyncStorage used in Expo app. Consider SecureStore for sensitive data.', 0, code)];
      }
      return [];
    },
  },

  // Payment related
  {
    id: 'PAY-001',
    title: 'Payment card data handling',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:cardNumber|card_number|creditCard)\s*[:=]/gi,
        /cvv\s*[:=]\s*['"`]?\d{3,4}/gi,
        /(?:expiry|expiryDate|exp_date)\s*[:=]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Payment card data handling detected. Use PCI-compliant payment SDKs only.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // API endpoint configuration
  {
    id: 'API-001',
    title: 'Hardcoded API endpoints',
    severity: 'low',
    run: (code) => {
      const results = [];
      const rx = /(?:API_URL|BASE_URL|ENDPOINT)\s*[:=]\s*['"`]https?:\/\/[^'"`]+['"`]/gi;
      let m;
      while ((m = rx.exec(code))) {
        results.push(makeFinding('Hardcoded API endpoint. Consider using environment-based configuration.', m.index, code, m[0]));
      }
      return results;
    },
  },

  // Social Media API Keys
  {
    id: 'KEY-FACEBOOK',
    title: 'Facebook App Secret',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:FB_APP_SECRET|facebook.*secret)\s*[:=]\s*['"`]([a-f0-9]{32})['"`]/gi,
      'Facebook App Secret detected. App secrets must never be in client code.'
    ),
  },

  {
    id: 'KEY-TWITTER',
    title: 'Twitter API Secret',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:consumer_secret|twitter.*secret)\s*[:=]\s*['"`]([A-Za-z0-9]{35,44})['"`]/gi,
      'Twitter API consumer secret detected. Remove immediately.'
    ),
  },

  // Database URLs
  {
    id: 'DB-URL-001',
    title: 'Database connection string',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:mongodb|postgresql|mysql):\/\/[^:]+:[^@]+@[^\s"'`;]+/gi,
      'Database connection string with credentials detected. Never expose database URLs in client code.'
    ),
  },

  // Admin/backdoor patterns
  {
    id: 'ADMIN-001',
    title: 'Hardcoded admin credentials',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:admin|root).*password\s*[:=]\s*['"`][^'"`]+['"`]/gi,
        /username\s*[:=]\s*['"`]admin['"`].*password/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Hardcoded admin credentials detected. Critical security vulnerability.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Environment variables exposure
  {
    id: 'ENV-002',
    title: 'Environment secrets in bundle',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /process\.env\.(?:SECRET|KEY|PASSWORD|TOKEN|PRIVATE)/gi,
        /REACT_NATIVE_(?:SECRET|KEY|PASSWORD|TOKEN)/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Environment secret may be bundled. Verify build process sanitizes secrets.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Analytics and tracking keys
  {
    id: 'KEY-ANALYTICS',
    title: 'Analytics write key',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:SEGMENT|MIXPANEL|AMPLITUDE).*(?:WRITE|SECRET).*KEY/gi,
      'Analytics write key detected. Use write keys only on server-side.'
    ),
  },

  // Push notification keys
  {
    id: 'KEY-PUSH',
    title: 'Push notification secret',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /(?:FCM|APNS).*(?:SERVER|PRIVATE).*KEY/gi,
      'Push notification server key detected. Server keys must not be in client apps.'
    ),
  },

  // Encryption key exposure
  {
    id: 'CRYPTO-001',
    title: 'Hardcoded encryption key',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:encryptionKey|encryption_key|cipher_key)\s*[:=]\s*['"`]([A-Za-z0-9+/=]{16,})['"`]/gi,
        /(?:AES|RSA).*key\s*[:=]\s*['"`]([A-Za-z0-9+/=]{16,})['"`]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Hardcoded encryption key detected. Keys must be securely generated and stored.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // URL scheme hijacking
  {
    id: 'RN-SCHEME-001',
    title: 'Custom URL scheme security',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /scheme\s*[:=]\s*['"`][a-z]+:\/\//gi,
      'Custom URL scheme detected. Validate all data from deep links to prevent injection.'
    ),
  },

  // WebView advanced threats
  {
    id: 'WV-002',
    title: 'WebView JavaScript bridge',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /postMessage|onMessage|injectJavaScript/gi,
      'WebView JavaScript bridge detected. Validate all messages between WebView and native code.'
    ),
  },

  // Third-party SDK keys
  {
    id: 'KEY-SDK',
    title: 'Third-party SDK keys',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const sdks = [
        'CRASHLYTICS', 'BUGSNAG', 'DATADOG', 'SENTRY_DSN',
        'ONESIGNAL', 'BRANCH_KEY', 'AMPLITUDE', 'MIXPANEL'
      ];
      for (const sdk of sdks) {
        const rx = new RegExp(`${sdk}.*[:=]\\s*['"\`]([A-Za-z0-9\\-_]{20,})['"\`]`, 'gi');
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding(`${sdk} key detected. Verify this is a client-side key, not a server key.`, m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // ========== AI Service API Keys ==========

  // OpenAI API Keys
  {
    id: 'KEY-OPENAI',
    title: 'OpenAI API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/g,
      'OpenAI API key detected. CRITICAL: Remove immediately - this is a SECRET key that allows unlimited API access and charges to your account.'
    ),
  },

  {
    id: 'KEY-OPENAI-PROJ',
    title: 'OpenAI Project API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /sk-proj-[a-zA-Z0-9_-]{43,}/g,
      'OpenAI project API key detected. Never expose OpenAI keys in client apps - use a backend proxy.'
    ),
  },

  {
    id: 'KEY-OPENAI-ORG',
    title: 'OpenAI Organization Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /sk-org-[a-zA-Z0-9]{48}/g,
      'OpenAI organization key detected. This gives access to your entire organization.'
    ),
  },

  // Anthropic (Claude) API Keys
  {
    id: 'KEY-ANTHROPIC',
    title: 'Anthropic (Claude) API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{95}/g,
      'Anthropic (Claude) API key detected. CRITICAL: Remove immediately - never expose AI API keys in mobile apps.'
    ),
  },

  // Google AI (PaLM, Gemini, Vertex)
  {
    id: 'KEY-GOOGLE-AI',
    title: 'Google AI API Key',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:GOOGLE_AI_KEY|GEMINI_API_KEY|PALM_API_KEY)\s*[:=]\s*['"`]([A-Za-z0-9_-]{39})['"`]/gi,
        /AIza[0-9A-Za-z_-]{35}(?=.*(?:gemini|palm|vertex|generative))/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Google AI/Gemini API key detected. Use server-side proxy for AI calls.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Cohere API Keys
  {
    id: 'KEY-COHERE',
    title: 'Cohere API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /[a-zA-Z0-9]{40}(?=.*cohere)/gi,
      'Cohere API key detected. AI API keys must be kept server-side only.'
    ),
  },

  // Hugging Face Tokens
  {
    id: 'KEY-HUGGINGFACE',
    title: 'Hugging Face Token',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /hf_[a-zA-Z0-9]{34,}/g,
      'Hugging Face access token detected. Keep tokens server-side to prevent abuse.'
    ),
  },

  // Azure OpenAI Keys
  {
    id: 'KEY-AZURE-OPENAI',
    title: 'Azure OpenAI Key',
    severity: 'critical',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:AZURE_OPENAI_KEY|AZURE_OPENAI_API_KEY)\s*[:=]\s*['"`]([a-f0-9]{32})['"`]/gi,
        /openai\.azure\.com.*(?:key|api-key).*['"`]([a-f0-9]{32})['"`]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Azure OpenAI API key detected. Use managed identity or key vault instead.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Replicate API Tokens
  {
    id: 'KEY-REPLICATE',
    title: 'Replicate API Token',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /r8_[a-zA-Z0-9]{40}/g,
      'Replicate API token detected. Keep AI service tokens on backend only.'
    ),
  },

  // AI21 Labs API Keys
  {
    id: 'KEY-AI21',
    title: 'AI21 Labs API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:AI21_API_KEY|ai21.*api.*key)\s*[:=]\s*['"`]([a-zA-Z0-9]{32,})['"`]/gi,
      'AI21 Labs API key detected. Never expose AI API keys in client applications.'
    ),
  },

  // General AI API key patterns
  {
    id: 'KEY-AI-GENERIC',
    title: 'Generic AI API Key Pattern',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:OPENAI|GPT|CLAUDE|ANTHROPIC|AI_KEY|LLM_KEY)\s*[:=]\s*['"`]sk-[a-zA-Z0-9_-]{20,}['"`]/gi,
        /(?:AI_API_KEY|LLM_API_KEY|GPT_KEY)\s*[:=]\s*['"`]([a-zA-Z0-9_-]{32,})['"`]/gi,
      ];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('AI/LLM API key pattern detected. Verify this is not a production key.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Stability AI (Stable Diffusion) Keys
  {
    id: 'KEY-STABILITY',
    title: 'Stability AI API Key',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /sk-[a-zA-Z0-9]{32,}(?=.*stability)/gi,
      'Stability AI API key detected. Image generation APIs should be proxied through backend.'
    ),
  },

  // Mistral AI Keys
  {
    id: 'KEY-MISTRAL',
    title: 'Mistral AI API Key',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /(?:MISTRAL_API_KEY|mistral.*api.*key)\s*[:=]\s*['"`]([a-zA-Z0-9]{32,})['"`]/gi,
      'Mistral AI API key detected. Keep all AI API keys server-side.'
    ),
  },
];

