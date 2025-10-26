/**
 * Permissions and Privacy Security Rules
 */
import { findRegex, makeFinding } from '../utils/scan-helpers.js';

export const PERMISSIONS_PRIVACY_RULES = [
  // Dangerous permissions
  {
    id: 'PERM-001',
    title: 'Camera permission usage',
    severity: 'medium',
    run: (code) => {
      const results = [];
      if (/CAMERA|requestCameraPermission|Camera\./.test(code)) {
        results.push(makeFinding('Camera permission detected. Ensure privacy policy discloses camera usage and purpose.', 0, code));
      }
      return results;
    },
  },

  {
    id: 'PERM-002',
    title: 'Microphone permission usage',
    severity: 'medium',
    run: (code) => {
      const results = [];
      if (/RECORD_AUDIO|requestMicrophonePermission|AudioRecord/.test(code)) {
        results.push(makeFinding('Microphone permission detected. Ensure privacy policy discloses audio recording.', 0, code));
      }
      return results;
    },
  },

  {
    id: 'PERM-003',
    title: 'Location permission usage',
    severity: 'medium',
    run: (code) => {
      const results = [];
      const patterns = [
        /ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION/g,
        /requestLocationPermission|getCurrentPosition|watchPosition/gi,
        /CLLocationManager/g,
      ];
      
      for (const rx of patterns) {
        if (rx.test(code)) {
          results.push(makeFinding('Location permission detected. Ensure privacy policy discloses location tracking and purpose.', 0, code));
          break;
        }
      }
      return results;
    },
  },

  {
    id: 'PERM-004',
    title: 'Contacts permission usage',
    severity: 'medium',
    run: (code) => {
      if (/READ_CONTACTS|WRITE_CONTACTS|requestContactsPermission/.test(code)) {
        return [makeFinding('Contacts permission detected. Ensure privacy disclosure for contact access.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PERM-005',
    title: 'Calendar permission usage',
    severity: 'low',
    run: (code) => {
      if (/READ_CALENDAR|WRITE_CALENDAR|requestCalendarPermission/.test(code)) {
        return [makeFinding('Calendar permission detected. Disclose calendar access in privacy policy.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PERM-006',
    title: 'SMS permission usage',
    severity: 'high',
    run: (code) => {
      if (/READ_SMS|SEND_SMS|RECEIVE_SMS/.test(code)) {
        return [makeFinding('SMS permission detected. This is a dangerous permission requiring clear justification.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PERM-007',
    title: 'Call log permission usage',
    severity: 'high',
    run: (code) => {
      if (/READ_CALL_LOG|WRITE_CALL_LOG|PROCESS_OUTGOING_CALLS/.test(code)) {
        return [makeFinding('Call log permission detected. Highly sensitive permission requiring strong justification.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PERM-008',
    title: 'Storage permission without scoped storage',
    severity: 'medium',
    run: (code) => {
      if (/READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE/.test(code) && !/scopedStorage|MediaStore/.test(code)) {
        return [makeFinding('Broad storage permission detected. Use scoped storage (Android 10+) instead.', 0, code)];
      }
      return [];
    },
  },

  // Privacy - Data collection
  {
    id: 'PRIV-001',
    title: 'Device ID collection',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /getDeviceId|getUniqueId|getAndroidId|identifierForVendor|advertisingIdentifier/gi,
      'Device identifier collection detected. Ensure GDPR/privacy compliance and user consent.'
    ),
  },

  {
    id: 'PRIV-002',
    title: 'IDFA/GAID collection',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /AdvertisingId|IDFA|getAdvertisingId|ASIdentifierManager/gi,
      'Advertising ID collection detected. Requires user consent (iOS 14.5+) and privacy disclosure.'
    ),
  },

  {
    id: 'PRIV-003',
    title: 'Biometric data collection',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /FaceID|TouchID|Biometric|FingerprintManager|BiometricPrompt/gi,
      'Biometric data usage detected. Ensure secure storage and privacy compliance.'
    ),
  },

  {
    id: 'PRIV-004',
    title: 'Health data access',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /HealthKit|GoogleFit|SensorManager.*(?:HEART_RATE|STEP_COUNTER)/gi,
      'Health data access detected. Requires explicit privacy disclosure and special handling.'
    ),
  },

  {
    id: 'PRIV-005',
    title: 'Clipboard access for tracking',
    severity: 'medium',
    run: (code) => {
      const results = [];
      // Check for clipboard access patterns that might be used for tracking
      const patterns = [
        /Clipboard\.getString\(\)(?!.*paste|.*user)/gi,
        /UIPasteboard.*string(?!.*paste)/gi,
      ];
      
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Automatic clipboard access detected. May violate privacy policies (iOS 14+ shows warning).', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'PRIV-006',
    title: 'Background location tracking',
    severity: 'high',
    run: (code) => findRegex(
      code,
      /ACCESS_BACKGROUND_LOCATION|allowsBackgroundLocationUpdates|startMonitoringSignificantLocationChanges/gi,
      'Background location tracking detected. Requires strong justification and explicit user consent.'
    ),
  },

  {
    id: 'PRIV-007',
    title: 'Screenshot/Screen recording prevention missing',
    severity: 'low',
    run: (code) => {
      // Check if handling sensitive data but not preventing screenshots
      if (/(?:password|pin|credit|card|ssn)/.test(code) && !/FLAG_SECURE|setScreenCaptureEnabled/.test(code)) {
        return [makeFinding('Sensitive data without screenshot prevention. Consider FLAG_SECURE (Android) to prevent screenshots.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PRIV-008',
    title: 'Bluetooth permission usage',
    severity: 'medium',
    run: (code) => {
      if (/BLUETOOTH|BLUETOOTH_ADMIN|BLUETOOTH_CONNECT|BLUETOOTH_SCAN/.test(code)) {
        return [makeFinding('Bluetooth permission detected. Disclose Bluetooth usage in privacy policy.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PRIV-009',
    title: 'Network state tracking',
    severity: 'low',
    run: (code) => {
      if (/ACCESS_NETWORK_STATE|ACCESS_WIFI_STATE/.test(code)) {
        return [makeFinding('Network state access detected. Can be used for fingerprinting.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'PRIV-010',
    title: 'Photo library access',
    severity: 'medium',
    run: (code) => {
      if (/READ_MEDIA_IMAGES|launchImageLibrary|PHPhotoLibrary/.test(code)) {
        return [makeFinding('Photo library access detected. Ensure privacy disclosure for media access.', 0, code)];
      }
      return [];
    },
  },
];

