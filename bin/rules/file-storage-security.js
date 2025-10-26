/**
 * File and Storage Security Rules
 */
import { findRegex, makeFinding } from '../utils/scan-helpers.js';

export const FILE_STORAGE_RULES = [
  // Unencrypted sensitive file references
  {
    id: 'FILE-001',
    title: 'Unencrypted sensitive file patterns',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /(?:\.env|\.plist|google-services\.json|Info\.plist|config\.json).*(?:password|secret|key|token)/gi,
        /readFile.*(?:\.env|\.plist|google-services\.json)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Accessing potentially unencrypted sensitive configuration file. Ensure secrets are properly secured.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Android external storage
  {
    id: 'FILE-002',
    title: 'Android external storage usage',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /EXTERNAL_STORAGE|getExternalStorage|ExternalStorageDirectory/gi,
      'External storage usage detected. Use scoped storage (Android 10+) for sensitive data.'
    ),
  },

  {
    id: 'FILE-003',
    title: 'Insecure file permissions',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /MODE_WORLD_READABLE|MODE_WORLD_WRITABLE/g,
        /chmod.*777/g,
        /FilePermission.*write/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Insecure file permissions detected. Files may be accessible by other apps.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // iOS file access
  {
    id: 'FILE-004',
    title: 'iOS unencrypted file storage',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /NSDocumentDirectory.*(?!.*NSFileProtection)/g,
        /\.documentDirectory.*write/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('iOS file storage without encryption protection. Consider NSFileProtectionComplete.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Secrets in resource files
  {
    id: 'FILE-005',
    title: 'Hardcoded resource file paths with secrets',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /['"]\.\.\/assets\/.*(?:key|secret|config|credential)/gi,
        /['"]\.\.\/res\/raw\/.*(?:key|secret|config)/gi,
        /Resources\/.*(?:key|secret|config)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Sensitive resource file reference. Ensure files in assets/res are not exposing secrets.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // File downloads without verification
  {
    id: 'FILE-006',
    title: 'Unverified file downloads',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /downloadFile\s*\([^)]*(?!.*verify|.*checksum|.*hash)/gi,
        /fetch.*\.download.*(?!.*integrity)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('File download without integrity verification. Validate checksums/signatures.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Cache directory sensitive data
  {
    id: 'FILE-007',
    title: 'Sensitive data in cache directory',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:CacheDirectory|caches).*(?:password|token|secret|key|credential)/gi,
      'Storing sensitive data in cache directory. Cache can be cleared and may not be secure.'
    ),
  },

  // SharedPreferences/UserDefaults security
  {
    id: 'FILE-008',
    title: 'Sensitive data in SharedPreferences/UserDefaults',
    severity: 'high',
    run: (code) => {
      const results = [];
      const patterns = [
        /SharedPreferences.*(?:password|token|secret|key|pin|credential)/gi,
        /UserDefaults.*(?:password|token|secret|key|pin|credential)/gi,
        /MMKV.*(?:password|token|secret|key)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Sensitive data in SharedPreferences/UserDefaults. Use Keychain/KeyStore for sensitive data.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Backup flags
  {
    id: 'FILE-009',
    title: 'Android backup enabled for sensitive data',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /allowBackup\s*=\s*true|backupAgent/gi,
      'Android backup may be enabled. Sensitive data could be backed up to cloud. Use android:allowBackup="false" for sensitive apps.'
    ),
  },

  // Temp file with sensitive data
  {
    id: 'FILE-010',
    title: 'Sensitive data in temporary files',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /(?:tmp|temp).*(?:password|token|secret|key|credential)/gi,
      'Storing sensitive data in temporary files. Ensure proper cleanup and use secure temp directories.'
    ),
  },
];

