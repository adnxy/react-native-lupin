/**
 * Authentication & Session Security Rules
 */
import { findRegex, makeFinding } from '../utils/scan-helpers.js';

export const AUTH_SESSION_RULES = [
  // Token storage
  {
    id: 'AUTH-001',
    title: 'JWT in AsyncStorage',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /AsyncStorage\.setItem\s*\([^)]*(?:jwt|token|auth).*eyJ[A-Za-z0-9]/gi,
      'JWT stored in AsyncStorage. Use SecureStore/Keychain for tokens.'
    ),
  },

  {
    id: 'AUTH-002',
    title: 'Tokens without SecureStore',
    severity: 'high',
    run: (code) => {
      // Check if storing tokens but not using secure storage
      const hasTokenStorage = /setItem.*(?:token|jwt|auth|credential)/gi.test(code);
      const hasSecureStore = /SecureStore|Keychain|KeyStore/gi.test(code);
      
      if (hasTokenStorage && !hasSecureStore) {
        return [makeFinding('Authentication tokens stored without secure storage. Use SecureStore (Expo) or react-native-keychain.', 0, code)];
      }
      return [];
    },
  },

  // Token expiration
  {
    id: 'AUTH-003',
    title: 'Missing token expiration check',
    severity: 'medium',
    run: (code) => {
      const hasTokenUsage = /jwt|token.*decode|parseJWT/gi.test(code);
      const hasExpirationCheck = /exp|expir|isExpired|isValid.*token/gi.test(code);
      
      if (hasTokenUsage && !hasExpirationCheck) {
        return [makeFinding('JWT/Token usage without expiration validation. Always verify token expiry.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'AUTH-004',
    title: 'Long-lived tokens',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:expires?In?|ttl|maxAge)\s*[:=]\s*(?:31536000|365\s*\*|999999)/gi,
      'Extremely long token expiration detected. Use shorter-lived tokens with refresh mechanism.'
    ),
  },

  // Refresh tokens
  {
    id: 'AUTH-005',
    title: 'Refresh token handling',
    severity: 'medium',
    run: (code) => {
      const hasAuthTokens = /accessToken|access_token/gi.test(code);
      const hasRefreshToken = /refreshToken|refresh_token/gi.test(code);
      
      if (hasAuthTokens && !hasRefreshToken) {
        return [makeFinding('Access tokens without refresh token mechanism. Implement token refresh for better security.', 0, code)];
      }
      return [];
    },
  },

  // OAuth security
  {
    id: 'AUTH-006',
    title: 'OAuth without PKCE',
    severity: 'high',
    run: (code) => {
      const hasOAuth = /oauth|authorize|authentication.*code/gi.test(code);
      const hasPKCE = /code_challenge|code_verifier|pkce/gi.test(code);
      
      if (hasOAuth && !hasPKCE) {
        return [makeFinding('OAuth flow without PKCE detected. Use PKCE (Proof Key for Code Exchange) for mobile OAuth.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'AUTH-007',
    title: 'OAuth redirect URI validation',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /redirect_uri\s*[:=]\s*['"]http(?!s)/gi,
      'Insecure OAuth redirect URI (HTTP). Always use HTTPS for OAuth redirects.'
    ),
  },

  {
    id: 'AUTH-008',
    title: 'OAuth state parameter missing',
    severity: 'high',
    run: (code) => {
      const hasOAuthAuth = /authorize\?.*client_id/gi.test(code);
      const hasState = /[?&]state=/gi.test(code);
      
      if (hasOAuthAuth && !hasState) {
        return [makeFinding('OAuth authorization without state parameter. Use state parameter to prevent CSRF attacks.', 0, code)];
      }
      return [];
    },
  },

  // Session management
  {
    id: 'AUTH-009',
    title: 'Session without timeout',
    severity: 'medium',
    run: (code) => {
      const hasSession = /session|authenticated|loggedIn/gi.test(code);
      const hasTimeout = /sessionTimeout|idle.*timeout|inactivity/gi.test(code);
      
      if (hasSession && !hasTimeout) {
        return [makeFinding('Session management without timeout. Implement automatic logout after inactivity.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'AUTH-010',
    title: 'Hardcoded session IDs',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /sessionId\s*[:=]\s*['"][a-f0-9]{32,}['"]/gi,
      'Hardcoded session ID detected. Session IDs must be dynamically generated.'
    ),
  },

  // API Key handling
  {
    id: 'AUTH-011',
    title: 'API keys in Authorization headers',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /Authorization\s*:\s*['"](?:Bearer\s+)?[A-Za-z0-9_\-]{32,}['"]/gi,
      'Hardcoded API key in Authorization header. Use backend proxy or secure key management.'
    ),
  },

  {
    id: 'AUTH-012',
    title: 'API keys in URL parameters',
    severity: 'critical',
    run: (code) => findRegex(
      code,
      /[?&](?:api_key|apikey|key|token)=[A-Za-z0-9_\-]{20,}/gi,
      'API key in URL parameters. Keys in URLs are logged and cached. Use headers instead.'
    ),
  },

  // Password handling
  {
    id: 'AUTH-013',
    title: 'Client-side password validation only',
    severity: 'medium',
    run: (code) => {
      const hasPasswordValidation = /validate.*password|password.*regex/gi.test(code);
      const hasServerValidation = /api.*validate|server.*check/gi.test(code);
      
      if (hasPasswordValidation && !hasServerValidation) {
        return [makeFinding('Password validation may be client-side only. Always validate passwords server-side.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'AUTH-014',
    title: 'Weak password requirements',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const weakPatterns = [
        /password.*length.*[<4]/gi,
        /password.*\.length\s*>=?\s*[1-5]\b/gi,
      ];
      
      for (const rx of weakPatterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Weak password requirements detected. Enforce strong password policies.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Biometric authentication
  {
    id: 'AUTH-015',
    title: 'Biometric fallback to insecure method',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /biometric.*fallback.*password\s*\|\|\s*true/gi,
        /TouchID.*onFail.*setAuthenticated\s*\(\s*true/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Insecure biometric authentication fallback. Fallback should require strong authentication.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // 2FA/MFA
  {
    id: 'AUTH-016',
    title: 'Missing two-factor authentication',
    severity: 'low',
    run: (code) => {
      const hasAuth = /login|signin|authenticate/gi.test(code);
      const has2FA = /2fa|mfa|two.*factor|otp|totp|authenticator/gi.test(code);
      
      if (hasAuth && !has2FA) {
        return [makeFinding('Authentication without 2FA/MFA detected. Consider implementing two-factor authentication.', 0, code)];
      }
      return [];
    },
  },

  // Remember me
  {
    id: 'AUTH-017',
    title: 'Insecure "Remember Me" implementation',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /rememberMe.*true.*setItem.*password/gi,
      'Insecure "Remember Me" storing password. Use secure tokens instead of passwords.'
    ),
  },

  // Certificate pinning for auth endpoints
  {
    id: 'AUTH-018',
    title: 'Auth endpoints without certificate pinning',
    severity: 'medium',
    run: (code) => {
      const hasAuthEndpoints = /\/api\/(?:login|auth|signin|token)/gi.test(code);
      const hasPinning = /certificatePinning|pinnedCertificates|trustkit/gi.test(code);
      
      if (hasAuthEndpoints && !hasPinning) {
        return [makeFinding('Authentication endpoints without certificate pinning. Consider SSL pinning for auth APIs.', 0, code)];
      }
      return [];
    },
  },

  // Social login
  {
    id: 'AUTH-019',
    title: 'Social login token validation',
    severity: 'high',
    run: (code) => {
      const hasSocialLogin = /(?:facebook|google|apple).*login|signInWith/gi.test(code);
      const hasValidation = /verify.*token|validate.*token/gi.test(code);
      
      if (hasSocialLogin && !hasValidation) {
        return [makeFinding('Social login without server-side token validation. Always verify social tokens server-side.', 0, code)];
      }
      return [];
    },
  },

  // Account enumeration
  {
    id: 'AUTH-020',
    title: 'Account enumeration vulnerability',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /user.*not.*found|email.*not.*registered|account.*does.*not.*exist/gi,
        /invalid.*username.*or.*password/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Specific error messages may enable account enumeration. Use generic error messages.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },
];

