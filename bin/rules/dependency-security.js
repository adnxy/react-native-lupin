/**
 * Dependency & Supply Chain Security Rules
 */
import { findRegex, makeFinding, hasModule } from '../utils/scan-helpers.js';

export const DEPENDENCY_RULES = [
  // Deprecated React Native modules
  {
    id: 'DEP-001',
    title: 'Deprecated React Native AsyncStorage',
    severity: 'medium',
    run: (code) => {
      if (/@react-native-community\/async-storage|AsyncStorage.*from.*react-native/.test(code)) {
        return [makeFinding('Deprecated @react-native-community/async-storage detected. Migrate to @react-native-async-storage/async-storage.', 0, code)];
      }
      return [];
    },
  },

  {
    id: 'DEP-002',
    title: 'Deprecated React Native NetInfo',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /NetInfo.*from.*['"]react-native['"]/g,
      'Deprecated NetInfo from react-native core. Use @react-native-community/netinfo.'
    ),
  },

  {
    id: 'DEP-003',
    title: 'Deprecated React Native WebView',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /WebView.*from.*['"]react-native['"]/g,
      'Deprecated WebView from react-native core. Use react-native-webview.'
    ),
  },

  {
    id: 'DEP-004',
    title: 'Deprecated React Native ListView',
    severity: 'low',
    run: (code) => findRegex(
      code,
      /ListView.*from.*['"]react-native['"]/g,
      'ListView is deprecated. Use FlatList or SectionList instead.'
    ),
  },

  {
    id: 'DEP-005',
    title: 'Deprecated React Native Geolocation',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /Geolocation.*from.*['"]react-native['"]/g,
      'Deprecated Geolocation from react-native core. Use @react-native-community/geolocation.'
    ),
  },

  {
    id: 'DEP-006',
    title: 'Deprecated React Native CameraRoll',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /CameraRoll.*from.*['"]react-native['"]/g,
      'Deprecated CameraRoll from react-native core. Use @react-native-camera-roll/camera-roll.'
    ),
  },

  {
    id: 'DEP-007',
    title: 'Deprecated React Native Clipboard',
    severity: 'medium',
    run: (code) => findRegex(
      code,
      /Clipboard.*from.*['"]react-native['"]/g,
      'Deprecated Clipboard from react-native core. Use @react-native-clipboard/clipboard.'
    ),
  },

  {
    id: 'DEP-008',
    title: 'Deprecated PropTypes from React',
    severity: 'low',
    run: (code) => findRegex(
      code,
      /PropTypes.*from.*['"]react['"]/g,
      'PropTypes deprecated in React. Use prop-types package or TypeScript.'
    ),
  },

  // Vulnerable patterns
  {
    id: 'DEP-009',
    title: 'Known vulnerable lodash usage',
    severity: 'medium',
    run: (code) => {
      // Check for vulnerable lodash patterns
      const patterns = [
        /lodash.*template\s*\(/gi,
        /_.template\s*\(/g,
      ];
      const results = [];
      for (const rx of patterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding('Lodash template has known vulnerabilities. Ensure lodash is updated to >= 4.17.21.', m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  {
    id: 'DEP-010',
    title: 'Outdated React Native version indicators',
    severity: 'medium',
    run: (code) => {
      const results = [];
      // Check for very old RN API patterns
      const oldPatterns = [
        { rx: /Navigator\s+from\s+['"]react-native['"]/g, msg: 'Navigator is deprecated since RN 0.44. Use react-navigation.' },
        { rx: /NavigatorIOS/g, msg: 'NavigatorIOS is deprecated. Use react-navigation.' },
        { rx: /ProgressBarAndroid/g, msg: 'ProgressBarAndroid may indicate old RN version. Consider using ActivityIndicator.' },
        { rx: /ToolbarAndroid/g, msg: 'ToolbarAndroid is deprecated. Use custom header or navigation library.' },
        { rx: /ViewPagerAndroid/g, msg: 'ViewPagerAndroid is deprecated. Use react-native-pager-view.' },
      ];
      
      for (const { rx, msg } of oldPatterns) {
        let m;
        while ((m = rx.exec(code))) {
          results.push(makeFinding(msg, m.index, code, m[0]));
        }
      }
      return results;
    },
  },

  // Supply chain - detect common vulnerable packages
  {
    id: 'DEP-011',
    title: 'Potential vulnerable npm package patterns',
    severity: 'high',
    run: (code) => {
      const results = [];
      // Common vulnerable package indicators
      const vulnerablePatterns = [
        { rx: /event-stream/gi, msg: 'event-stream package had known backdoor. Verify version and necessity.' },
        { rx: /flatmap-stream/gi, msg: 'flatmap-stream was involved in npm supply chain attack. Audit usage.' },
      ];
      
      for (const { rx, msg } of vulnerablePatterns) {
        if (rx.test(code)) {
          results.push(makeFinding(msg, 0, code));
        }
      }
      return results;
    },
  },
];

