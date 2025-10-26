#!/usr/bin/env node
/**
 * lupin.js — Static bundle security scanner for Expo/React Native
 * ---------------------------------------------------------------
 * Scans compiled JS bundles for risky patterns: hard-coded secrets,
 * eval, insecure http URLs, and more.
 *
 * Usage:
 *   # Auto-detect project and find bundles
 *   lupin
 *
 *   # Specify project type
 *   lupin --type expo
 *   lupin --type rn-cli
 *
 *   # Scan all found bundles without prompting
 *   lupin --scan-all
 *
 *   # Manual mode - specify bundle directly
 *   lupin --bundle path/to/main.jsbundle
 *   lupin -b ./dist/_expo/static/js/ios/entry-*.js
 *
 *   # With JSON report and custom fail level
 *   lupin --json report.json --fail-level high
 *
 * Exit codes:
 *   0 = no findings at/above fail level
 *   1 = findings at/above fail level
 */

import fs from 'fs';
import path from 'path';
import { program } from 'commander';
import { glob } from 'glob';
import { Buffer } from 'buffer';

let chalk;
try {
  chalk = (await import('chalk')).default;
} catch {
  chalk = new Proxy({}, { get: () => (x) => x }); // noop if chalk missing
}

/** ---------- Utilities ---------- */

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function severityGte(a, b) {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

function shannonEntropy(str) {
  // Basic entropy detection for secrets (works on minified bundles too)
  const map = new Map();
  for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
  const len = str.length || 1;
  let ent = 0;
  for (const [, count] of map) {
    const p = count / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function maybeBase64ish(s) {
  return /^[A-Za-z0-9+/=]+$/.test(s);
}
function maybeHexish(s) {
  return /^[a-f0-9]+$/i.test(s);
}

function loadBundle(filepath) {
  if (!fs.existsSync(filepath)) {
    throw new Error(`Bundle not found: ${filepath}`);
  }
  return fs.readFileSync(filepath, 'utf8');
}

function readJsonSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

/** ---------- Rules ---------- */
/**
 * Each rule returns array of findings:
 * { id, title, severity, message, snippet, position }
 */
const RULES = [
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

/** ---------- Core scanning helpers ---------- */

function findRegex(code, regex, message) {
  const results = [];
  let m;
  while ((m = regex.exec(code))) {
    results.push(makeFinding(message, m.index, code, m[0]));
  }
  return results;
}

function makeFinding(message, idx, code, matchText) {
  return {
    message,
    position: idx,
    snippet: makeSnippet(code, idx),
    match: matchText,
  };
}

function makeSnippet(code, idx, context = 60) {
  const start = Math.max(0, idx - context);
  const end = Math.min(code.length, idx + context);
  return code.slice(start, end).replace(/\n/g, ' ');
}

function slicePreview(s, max = 100) {
  if (s.length <= max) return s;
  return s.slice(0, Math.floor(max / 2)) + '…' + s.slice(s.length - Math.floor(max / 2));
}

/** ---------- Formatter ---------- */

function formatTable(findings) {
  const lines = [];
  const cols = ['ID', 'Severity', 'Title', 'Message/Match', 'Pos'];
  const widths = [10, 9, 26, 56, 8];

  function pad(str = '', w) {
    const s = (str + '').replace(/\s+/g, ' ');
    return s.length > w ? s.slice(0, w - 1) + '…' : s.padEnd(w);
  }

  lines.push(
    chalk.bold(
      [pad(cols[0], widths[0]), pad(cols[1], widths[1]), pad(cols[2], widths[2]), pad(cols[3], widths[3]), pad(cols[4], widths[4])].join(
        '  '
      )
    )
  );

  for (const f of findings) {
    const sevColor =
      f.severity === 'critical'
        ? chalk.bold.magenta
        : f.severity === 'high'
        ? chalk.red
        : f.severity === 'medium'
        ? chalk.yellow
        : f.severity === 'low'
        ? chalk.blue
        : chalk.gray;

    lines.push(
      [
        pad(f.id, widths[0]),
        pad(sevColor(f.severity.toUpperCase()), widths[1]),
        pad(f.title, widths[2]),
        pad(f.match ? `${f.message} (${slicePreview(f.match, 48)})` : f.message, widths[3]),
        pad(String(f.position ?? '-'), widths[4]),
      ].join('  ')
    );
  }
  return lines.join('\n');
}

/** ---------- Project type detection & bundle discovery ---------- */

function detectProjectType(baseDir = process.cwd()) {
  // Check for Expo
  const appJsonPath = path.join(baseDir, 'app.json');
  if (fs.existsSync(appJsonPath)) {
    try {
      const appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
      if (appJson.expo) return 'expo';
    } catch {}
  }

  // Check for RN CLI
  const hasAndroid = fs.existsSync(path.join(baseDir, 'android'));
  const hasIos = fs.existsSync(path.join(baseDir, 'ios'));
  const packageJsonPath = path.join(baseDir, 'package.json');
  
  if ((hasAndroid || hasIos) && fs.existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      if (pkg.dependencies?.['react-native'] || pkg.devDependencies?.['react-native']) {
        return 'rn-cli';
      }
    } catch {}
  }

  return null;
}

async function findBundles(projectType, baseDir = process.cwd()) {
  const bundles = [];

  if (projectType === 'expo') {
    // Expo bundles are in dist/_expo/static/js/{platform}/
    const patterns = [
      'dist/_expo/static/js/**/*.js',
      '.expo/static/js/**/*.js',
      'web-build/static/js/**/*.js'
    ];
    
    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => 
          // Exclude tiny files, likely not main bundles
          fs.statSync(f).size > 10000
        ));
      } catch {}
    }
  } else if (projectType === 'rn-cli') {
    // React Native CLI bundles
    const patterns = [
      'android/app/build/generated/assets/react/**/index.android.bundle',
      'android/app/src/main/assets/index.android.bundle',
      'ios/build/**/main.jsbundle',
      'ios/main.jsbundle',
      '*.bundle' // fallback
    ];

    for (const pattern of patterns) {
      try {
        const files = await glob(pattern, { cwd: baseDir, absolute: true });
        bundles.push(...files.filter(f => 
          fs.statSync(f).size > 10000
        ));
      } catch {}
    }
  }

  // Remove duplicates
  return [...new Set(bundles)];
}

function promptUser(question) {
  return new Promise((resolve) => {
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });
    readline.question(question, (answer) => {
      readline.close();
      resolve(answer.trim());
    });
  });
}

/** ---------- CLI ---------- */

program
  .option('-b, --bundle <path>', 'Path to compiled JS bundle (manual mode)')
  .option('-t, --type <type>', 'Project type: expo or rn-cli (auto-detects if not specified)')
  .option('-s, --sourcemap <path>', 'Optional path to source map (for future mapping enhancements)')
  .option('--json [outfile]', 'Write JSON report (default: lupin-report-{timestamp}.json). Enabled by default.')
  .option('--no-json', 'Disable automatic JSON report generation')
  .option('--fail-level <level>', 'Exit non-zero if any finding >= level (info|low|medium|high|critical)', 'medium')
  .option('--show-level <level>', 'Only display findings >= level on screen (info|low|medium|high|critical). JSON contains all.', 'medium')
  .option('--max-findings <n>', 'Limit number of findings (for noisy bundles)', (v) => parseInt(v, 10), 5000)
  .option('--scan-all', 'Scan all found bundles without prompting')
  .option('--no-color', 'Disable colored output')
  .parse(process.argv);

const opts = program.opts();

// Auto-generate JSON report filename if enabled and no filename provided
if (opts.json !== false) {
  if (opts.json === true || opts.json === undefined) {
    // Generate default filename with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    opts.json = `lupin-report-${timestamp}.json`;
  }
}

(async function main() {
  try {
    let bundlesToScan = [];

    // Manual mode: user specified a bundle
    if (opts.bundle) {
      bundlesToScan = [path.resolve(opts.bundle)];
    } else {
      // Auto-discovery mode
      console.log(`
${chalk.bold.cyan('╔═══════════════════════════════════════════════════════════════════════════════╗')}
${chalk.bold.cyan('║')}${' '.repeat(79)}${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}          ${chalk.bold.magenta('🔒 LUPIN')} ${chalk.bold.white('━')} ${chalk.bold.cyan('Bundle Security Scanner')}                     ${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}          ${chalk.gray('React Native & Expo Security Auditor')}                      ${chalk.bold.cyan('║')}
${chalk.bold.cyan('║')}${' '.repeat(79)}${chalk.bold.cyan('║')}
${chalk.bold.cyan('╚═══════════════════════════════════════════════════════════════════════════════╝')}
`);

      // Detect or use specified project type
      let projectType = opts.type?.toLowerCase();
      if (!projectType) {
        projectType = detectProjectType();
        if (projectType) {
          console.log(chalk.cyan(`✓ Detected project type: ${projectType}`));
        } else {
          console.log(chalk.yellow('⚠ Could not auto-detect project type.'));
          const answer = await promptUser('Enter project type (expo/rn-cli): ');
          projectType = answer.toLowerCase();
          if (!['expo', 'rn-cli'].includes(projectType)) {
            throw new Error('Invalid project type. Use "expo" or "rn-cli"');
          }
        }
      } else {
        console.log(chalk.cyan(`✓ Using specified project type: ${projectType}`));
      }

      // Find bundles
      console.log(chalk.gray('Searching for bundle files...'));
      const foundBundles = await findBundles(projectType);

      if (foundBundles.length === 0) {
        console.log(chalk.red('\n✗ No bundle files found.'));
        console.log(chalk.gray('\nTips:'));
        console.log(chalk.gray('  - For Expo: run "npx expo export" first'));
        console.log(chalk.gray('  - For RN CLI: build your app first'));
        console.log(chalk.gray('  - Or use: --bundle <path> to specify manually'));
        process.exit(1);
      }

      console.log(chalk.green(`  ✨ Found ${chalk.bold.white(foundBundles.length)} bundle file(s)\n`));
      console.log(chalk.gray(`  ╭${'─'.repeat(76)}╮`));
      foundBundles.forEach((b, i) => {
        const size = Math.round(fs.statSync(b).size / 1024);
        const relativePath = path.relative(process.cwd(), b);
        const displayPath = relativePath.length > 60 ? '...' + relativePath.slice(-57) : relativePath;
        const sizeStr = `${size.toLocaleString()} KB`;
        const numberColor = i === 0 ? chalk.cyan : chalk.gray;
        console.log(chalk.gray(`  │ `) + numberColor(`${i + 1}. `) + chalk.white(displayPath.padEnd(62)) + chalk.cyan(sizeStr.padStart(8)) + chalk.gray(` │`));
      });
      console.log(chalk.gray(`  ╰${'─'.repeat(76)}╯`));

      // Determine which bundles to scan
      if (opts.scanAll || foundBundles.length === 1) {
        bundlesToScan = foundBundles;
      } else {
        const answer = await promptUser('\nScan all bundles? (y/n) or enter number to scan specific: ');
        if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
          bundlesToScan = foundBundles;
        } else if (answer.match(/^\d+$/)) {
          const idx = parseInt(answer, 10) - 1;
          if (idx >= 0 && idx < foundBundles.length) {
            bundlesToScan = [foundBundles[idx]];
          } else {
            throw new Error('Invalid bundle number');
          }
        } else {
          bundlesToScan = [foundBundles[0]]; // default to first
        }
      }
      console.log('');
    }

    // Scan each bundle
    let allFindings = [];
    let hasBlockingFindings = false;

    for (const bundlePath of bundlesToScan) {
      console.log(chalk.gray('\n  ⏳ Loading bundle...'));
      const code = loadBundle(bundlePath);
      console.log(chalk.green(`  ✓ Loaded ${Math.round(Buffer.byteLength(code, 'utf8') / 1024).toLocaleString()} KB`));
      
      const sourcemap = opts.sourcemap ? readJsonSafe(path.resolve(opts.sourcemap)) : null;

      const meta = {
        file: bundlePath,
        sizeBytes: Buffer.byteLength(code, 'utf8'),
        hasSourceMapURL: /sourceMappingURL=/.test(code),
        sourcemapLoaded: !!sourcemap,
        scannedAt: new Date().toISOString(),
        runtimeHint: detectRuntime(code),
      };

      // Scanning animation
      console.log(chalk.cyan('\n  🔍 Running security scan'));
      console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
      
      const findingsRaw = [];
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      
      for (let i = 0; i < RULES.length; i++) {
        const rule = RULES[i];
        
        // Show progress
        const progress = Math.round(((i + 1) / RULES.length) * 100);
        const barLength = 30;
        const filled = Math.round((progress / 100) * barLength);
        const empty = barLength - filled;
        
        // Gradient progress bar
        const barColor = progress < 33 ? chalk.cyan : progress < 66 ? chalk.blue : chalk.green;
        const bar = barColor('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
        
        process.stdout.write(`\r  ${bar} ${chalk.bold.white(progress + '%')} ${chalk.gray('│')} ${chalk.gray(rule.title.padEnd(35).slice(0, 35))}`);
        
        const res = rule.run(code).map((f) => ({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          ...f,
        }));
        
        // Real-time detection alerts
        if (res.length > 0) {
          process.stdout.write('\r' + ' '.repeat(80) + '\r'); // Clear line
          const severityColor = 
            rule.severity === 'critical' ? chalk.bold.magenta :
            rule.severity === 'high' ? chalk.red :
            rule.severity === 'medium' ? chalk.yellow :
            chalk.gray;
          
          const icon = rule.severity === 'critical' ? '🔥' : rule.severity === 'high' ? '⚠️' : rule.severity === 'medium' ? '⚡' : '•';
          console.log(`  ${icon} Found ${chalk.bold.white(res.length)} ${severityColor(rule.severity.toUpperCase())} ${chalk.gray('·')} ${chalk.white(rule.title)}`);
          
          // Count by severity
          if (rule.severity === 'critical') criticalCount += res.length;
          else if (rule.severity === 'high') highCount += res.length;
          else if (rule.severity === 'medium') mediumCount += res.length;
        }
        
        findingsRaw.push(...res);
        if (findingsRaw.length >= opts.maxFindings) break;
      }
      
      // Clear progress line
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      
      // Scan complete message - compact format
      console.log('');
      if (criticalCount > 0) {
        console.log(chalk.magenta(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.magenta(`  │`) + `  🚨  ${chalk.bold.magenta(`${criticalCount} CRITICAL`)} ${chalk.magenta('issue(s) detected')}`.padEnd(61) + chalk.magenta(`│`));
        console.log(chalk.magenta(`  └${'─'.repeat(50)}┘`));
      } else if (highCount > 0) {
        console.log(chalk.red(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.red(`  │`) + `  ⚠️   ${chalk.bold.red(`${highCount} HIGH`)} ${chalk.red('severity issue(s) detected')}`.padEnd(62) + chalk.red(`│`));
        console.log(chalk.red(`  └${'─'.repeat(50)}┘`));
      } else if (mediumCount > 0) {
        console.log(chalk.yellow(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.yellow(`  │`) + `  ⚡  ${chalk.bold.yellow(`${mediumCount} MEDIUM`)} ${chalk.yellow('issue(s) detected')}`.padEnd(62) + chalk.yellow(`│`));
        console.log(chalk.yellow(`  └${'─'.repeat(50)}┘`));
      } else {
        console.log(chalk.green(`  ┌${'─'.repeat(50)}┐`));
        console.log(chalk.green(`  │`) + `  ✨  ${chalk.bold.green('Scan complete - no high-severity issues')}  `.padEnd(61) + chalk.green(`│`));
        console.log(chalk.green(`  └${'─'.repeat(50)}┘`));
      }

      // Deduplicate near-identical matches
      const dedupKey = (f) => `${f.id}:${f.match || f.message}:${Math.floor((f.position || 0) / 50)}`;
      const dedup = new Map();
      for (const f of findingsRaw) {
        const k = dedupKey(f);
        if (!dedup.has(k)) dedup.set(k, f);
      }
      const findings = [...dedup.values()];

      // Sort by severity then position
      findings.sort((a, b) => {
        const sev = SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
        if (sev !== 0) return sev;
        return (a.position || 0) - (b.position || 0);
      });

      // Console output
      if (bundlesToScan.length > 1) {
        console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}`));
      }
      const fileName = path.basename(meta.file);
      const fileDir = path.relative(process.cwd(), path.dirname(meta.file));
      console.log(chalk.bold.cyan(`\n  📦 Bundle Analysis`));
      console.log(chalk.gray(`  ╭${'─'.repeat(86)}╮`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📄 File:     `) + chalk.white(fileName.length > 66 ? fileName.slice(0, 63) + '...' : fileName.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📁 Location: `) + chalk.gray((fileDir || '.').padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`💾 Size:     `) + chalk.yellow(`${Math.round(meta.sizeBytes / 1024).toLocaleString()} KB`.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`⚙️  Runtime:  `) + chalk.white(meta.runtimeHint.padEnd(66)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`🗺️  Source:   `) + (meta.hasSourceMapURL ? chalk.green('✓ SourceMap URL found') : chalk.gray('✗ No source map')).padEnd(77) + chalk.gray(` │`));
      console.log(chalk.gray(`  ╰${'─'.repeat(86)}╯`));
      console.log('');

      // Filter findings for display based on --show-level
      const showLevel = (opts.showLevel || 'medium').toLowerCase();
      const displayFindings = findings.filter(f => severityGte(f.severity, showLevel));
      
      // Show severity breakdown for ALL findings
      const severityCounts = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      if (findings.length === 0) {
        console.log(chalk.green(`  ╭${'─'.repeat(50)}╮`));
        console.log(chalk.green(`  │`) + chalk.green.bold(`  ✅  No security findings! Bundle looks clean.    `).padEnd(61) + chalk.green(`│`));
        console.log(chalk.green(`  ╰${'─'.repeat(50)}╯\n`));
      } else {
        console.log(chalk.bold.white(`  📊 Scan Results`));
        console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
        console.log(chalk.white(`  ${chalk.bold('Total Findings:')} ${chalk.cyan(findings.length)}\n`));
        
        // Show breakdown first
        console.log(chalk.gray(`  Severity Breakdown:`));
        console.log(chalk.gray(`  ╭${'─'.repeat(36)}╮`));
        if (severityCounts.critical) console.log(chalk.gray(`  │ `) + chalk.bold.magenta(` 🔥 CRITICAL   `) + chalk.magenta(`${severityCounts.critical}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.high) console.log(chalk.gray(`  │ `) + chalk.red.bold(` ⚠️  HIGH       `) + chalk.red(`${severityCounts.high}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.medium) console.log(chalk.gray(`  │ `) + chalk.yellow.bold(` ⚡ MEDIUM     `) + chalk.yellow(`${severityCounts.medium}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.low) console.log(chalk.gray(`  │ `) + chalk.blue.bold(` ℹ️  LOW        `) + chalk.blue(`${severityCounts.low}`.padStart(3)) + chalk.gray('                │'));
        if (severityCounts.info) console.log(chalk.gray(`  │ `) + chalk.cyan.bold(` 💡 INFO       `) + chalk.cyan(`${severityCounts.info}`.padStart(3)) + chalk.gray('                │'));
        console.log(chalk.gray(`  ╰${'─'.repeat(36)}╯\n`));
        
        // Display filtered findings
        if (displayFindings.length === 0) {
          console.log(chalk.green(`  ✅ No findings at or above ${chalk.bold(showLevel.toUpperCase())} level`));
          console.log(chalk.gray(`  ${findings.length} lower-severity finding(s) hidden · Use --show-level to adjust\n`));
        } else {
          console.log(chalk.bold.white(`  📋 Detailed Findings`) + chalk.gray(` (${displayFindings.length} shown · >= ${showLevel.toUpperCase()})`));
          console.log(chalk.gray(`  ${'━'.repeat(40)}\n`));
          console.log(formatTable(displayFindings));
          console.log('');
        }
        
        // Mention JSON export if there are more findings
        if (displayFindings.length < findings.length) {
          console.log(chalk.gray(`  💡 ${findings.length - displayFindings.length} additional lower-severity finding(s) hidden · Use ${chalk.white('--show-level')} to view all\n`));
        }
      }

      allFindings.push(...findings.map(f => ({ ...f, bundle: bundlePath })));

      // JSON report per bundle (contains ALL findings, not filtered)
      if (opts.json !== false && bundlesToScan.length === 1) {
        const report = { 
          meta, 
          findings,
          summary: {
            total: findings.length,
            severityBreakdown: severityCounts,
            displayedOnScreen: displayFindings.length,
            showLevel: showLevel
          }
        };
        fs.writeFileSync(path.resolve(opts.json), JSON.stringify(report, null, 2), 'utf8');
        console.log(chalk.cyan(`  📄 Full report (${chalk.bold.white(findings.length)} findings) → `) + chalk.bold.white(opts.json));
      }

      // Check fail level
      const failLevel = (opts.failLevel || 'medium').toLowerCase();
      const hasBlocking = findings.some((f) => severityGte(f.severity, failLevel));
      if (hasBlocking) hasBlockingFindings = true;
    }

    // Multi-bundle JSON report (contains ALL findings)
    if (opts.json !== false && bundlesToScan.length > 1) {
      const overallSeverity = allFindings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      const report = {
        scannedAt: new Date().toISOString(),
        bundles: bundlesToScan.length,
        totalFindings: allFindings.length,
        findings: allFindings,
        summary: {
          severityBreakdown: overallSeverity,
          showLevel: opts.showLevel || 'medium'
        }
      };
      fs.writeFileSync(path.resolve(opts.json), JSON.stringify(report, null, 2), 'utf8');
      console.log(chalk.cyan(`  📄 Full report (${chalk.bold.white(allFindings.length)} findings) → `) + chalk.bold.white(opts.json));
    }

    // Summary
    if (bundlesToScan.length > 1) {
      console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}`));
      console.log(chalk.bold.white(`\n  📊 Overall Summary\n`));
      console.log(chalk.gray(`  ╭${'─'.repeat(86)}╮`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`📦 Bundles Scanned: `) + chalk.bold.white(bundlesToScan.length.toString().padEnd(64)) + chalk.gray(` │`));
      console.log(chalk.gray(`  │ `) + chalk.cyan(`🔍 Total Findings:  `) + chalk.bold.yellow(allFindings.length.toString().padEnd(64)) + chalk.gray(` │`));
      
      // Overall severity breakdown
      const overallSeverity = allFindings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      
      if (Object.keys(overallSeverity).length > 0) {
        console.log(chalk.gray(`  ├${'─'.repeat(86)}┤`));
        if (overallSeverity.critical) console.log(chalk.gray(`  │ `) + chalk.bold.magenta(` 🔥 CRITICAL   `) + chalk.magenta(`${overallSeverity.critical}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.high) console.log(chalk.gray(`  │ `) + chalk.red.bold(` ⚠️  HIGH       `) + chalk.red(`${overallSeverity.high}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.medium) console.log(chalk.gray(`  │ `) + chalk.yellow.bold(` ⚡ MEDIUM     `) + chalk.yellow(`${overallSeverity.medium}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.low) console.log(chalk.gray(`  │ `) + chalk.blue.bold(` ℹ️  LOW        `) + chalk.blue(`${overallSeverity.low}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
        if (overallSeverity.info) console.log(chalk.gray(`  │ `) + chalk.cyan.bold(` 💡 INFO       `) + chalk.cyan(`${overallSeverity.info}`.padStart(3).padEnd(67)) + chalk.gray(` │`));
      }
      
      console.log(chalk.gray(`  ╰${'─'.repeat(86)}╯`));
    }

    // CI fail level
    const failLevel = (opts.failLevel || 'medium').toLowerCase();
    console.log(chalk.bold.cyan(`\n${'═'.repeat(90)}\n`));
    
    if (hasBlockingFindings) {
      console.log(chalk.magenta(`  ╭${'─'.repeat(60)}╮`));
      console.log(chalk.magenta(`  │`) + `  ⛔  ${chalk.bold.magenta('SECURITY CHECK FAILED')}                           `.padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  ├${'─'.repeat(60)}┤`));
      console.log(chalk.magenta(`  │`) + chalk.white(`  Findings at or above ${chalk.bold.magenta(failLevel.toUpperCase())} level detected`).padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  │`) + chalk.gray(`  Please review and address security issues`).padEnd(71) + chalk.magenta(`│`));
      console.log(chalk.magenta(`  ╰${'─'.repeat(60)}╯\n`));
      if (opts.json !== false) {
        console.log(chalk.cyan(`  📋 Full report: `) + chalk.bold.white(opts.json));
      }
      console.log(chalk.gray(`\n  Exit code: 1\n`));
      process.exit(1);
    } else {
      console.log(chalk.green(`  ╭${'─'.repeat(60)}╮`));
      console.log(chalk.green(`  │`) + `  ✅  ${chalk.bold.green('SECURITY CHECK PASSED')}                          `.padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  ├${'─'.repeat(60)}┤`));
      console.log(chalk.green(`  │`) + chalk.white(`  No findings at or above ${chalk.bold.cyan(failLevel.toUpperCase())} level`).padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  │`) + chalk.gray(`  Bundle is ready for deployment!`).padEnd(71) + chalk.green(`│`));
      console.log(chalk.green(`  ╰${'─'.repeat(60)}╯\n`));
      if (opts.json !== false) {
        console.log(chalk.cyan(`  📋 Full report: `) + chalk.bold.white(opts.json));
      }
      console.log(chalk.gray(`\n  Exit code: 0\n`));
      process.exit(0);
    }
  } catch (err) {
    console.error(chalk.red(`\n❌ Lupin error: ${err.message}`));
    process.exit(1);
  }
})();

/** ---------- Helpers ---------- */

function detectRuntime(code) {
  // Very rough hints to tell if bundle came from RN/Expo/Hermes
  if (/HermesInternal/.test(code)) return 'React Native (Hermes)';
  if (/__expo/.test(code) || /expo\./.test(code)) return 'Expo';
  if (/worklet/.test(code)) return 'Reanimated present';
  return 'Unknown';
}
