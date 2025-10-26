# API Documentation

Complete reference for using Lupin Security Scanner programmatically in your Node.js applications.

## Installation

```bash
npm install lupin-security-scanner
```

## Quick Start

```javascript
import { scanBundle } from 'lupin-security-scanner';

const result = await scanBundle('./dist/bundle.js');
console.log(`Found ${result.totalFindings} issues`);
```

---

## Core Functions

### `scanBundle(bundlePath, options)`

Scan a single JavaScript bundle for security vulnerabilities.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `bundlePath` | string | ✅ | - | Path to the JavaScript bundle file |
| `options` | object | ❌ | `{}` | Configuration options |
| `options.maxFindings` | number | ❌ | `5000` | Maximum number of findings to return |
| `options.failLevel` | string | ❌ | `'medium'` | Minimum severity level for `hasBlockingFindings` |
| `options.showLevel` | string | ❌ | `'medium'` | Minimum severity level to include in `findings` |

**Returns:** `Promise<ScanResult>`

**Example:**

```javascript
import { scanBundle } from 'lupin-security-scanner';

const result = await scanBundle('./dist/production.js', {
  failLevel: 'high',      // Only fail on high/critical
  showLevel: 'medium',    // Show medium and above
  maxFindings: 1000       // Limit findings
});

if (result.hasBlockingFindings) {
  console.error('❌ Security issues found!');
  console.log(`Critical: ${result.severityBreakdown.critical || 0}`);
  console.log(`High: ${result.severityBreakdown.high || 0}`);
  process.exit(1);
}

console.log('✅ Security check passed!');
```

**Return Type:**

```typescript
interface ScanResult {
  // Paths and metadata
  bundlePath: string;                    // Path to scanned bundle
  
  // Finding counts
  totalFindings: number;                 // Total findings (all severities)
  displayedFindings: number;             // Findings matching showLevel
  
  // Findings arrays
  findings: Finding[];                   // Filtered by showLevel
  allFindings: Finding[];                // All findings
  
  // Status flags
  hasBlockingFindings: boolean;          // True if any finding >= failLevel
  
  // Configuration
  failLevel: string;                     // Configured fail level
  showLevel: string;                     // Configured show level
  
  // Severity breakdown
  severityBreakdown: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
  
  // Bundle metadata
  meta: {
    sizeBytes: number;                   // Bundle size in bytes
    hasSourceMapURL: boolean;            // Source map detected
    scannedAt: string;                   // ISO timestamp
    runtimeHint: string;                 // Detected runtime
  };
}
```

---

### `scanMultipleBundles(bundlePaths, options)`

Scan multiple JavaScript bundles in a single operation.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `bundlePaths` | string[] | ✅ | - | Array of bundle file paths |
| `options` | object | ❌ | `{}` | Same options as `scanBundle` |

**Returns:** `Promise<MultiBundleScanResult>`

**Example:**

```javascript
import { scanMultipleBundles } from 'lupin-security-scanner';

const bundles = [
  './dist/ios-bundle.js',
  './dist/android-bundle.js',
  './dist/web-bundle.js'
];

const result = await scanMultipleBundles(bundles, {
  failLevel: 'high'
});

console.log(`Scanned ${result.totalBundles} bundles`);
console.log(`Total findings: ${result.totalFindings}`);

// Check each bundle individually
result.bundles.forEach((bundle, i) => {
  console.log(`\nBundle ${i + 1}: ${bundle.bundlePath}`);
  console.log(`  Findings: ${bundle.totalFindings}`);
  console.log(`  Has blocking: ${bundle.hasBlockingFindings}`);
});

// Overall status
if (result.hasBlockingFindings) {
  console.error('\n❌ One or more bundles have security issues!');
  process.exit(1);
}
```

**Return Type:**

```typescript
interface MultiBundleScanResult {
  // Individual bundle results
  bundles: ScanResult[];                 // Array of scan results
  
  // Aggregate data
  totalBundles: number;                  // Number of bundles scanned
  totalFindings: number;                 // Total findings across all bundles
  allFindings: Finding[];                // All findings with bundle info
  
  // Status
  hasBlockingFindings: boolean;          // True if any bundle has blocking findings
  
  // Aggregate severity breakdown
  severityBreakdown: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
  
  // Metadata
  scannedAt: string;                     // ISO timestamp
}
```

---

### `detectProjectType(baseDir)`

Auto-detect whether a directory contains an Expo or React Native CLI project.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `baseDir` | string | ❌ | `process.cwd()` | Directory to check |

**Returns:** `'expo' | 'rn-cli' | null`

**Example:**

```javascript
import { detectProjectType } from 'lupin-security-scanner';

// Check current directory
const type = detectProjectType();
console.log(`Project type: ${type}`); // 'expo', 'rn-cli', or null

// Check specific directory
const otherType = detectProjectType('./my-app');

if (type === 'expo') {
  console.log('Detected Expo project');
} else if (type === 'rn-cli') {
  console.log('Detected React Native CLI project');
} else {
  console.log('Unknown or no React Native project');
}
```

**Detection Logic:**

- **Expo**: Checks for `app.json` with `expo` property
- **React Native CLI**: Checks for `android/` or `ios/` directories + `react-native` in `package.json`

---

### `findBundles(projectType, baseDir)`

Automatically discover bundle files for a given project type.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `projectType` | string | ✅ | - | `'expo'` or `'rn-cli'` |
| `baseDir` | string | ❌ | `process.cwd()` | Directory to search |

**Returns:** `Promise<string[]>` - Array of absolute paths to bundle files

**Example:**

```javascript
import { detectProjectType, findBundles } from 'lupin-security-scanner';

// Auto-detect and find bundles
const projectType = detectProjectType();
if (!projectType) {
  throw new Error('No React Native project found');
}

const bundles = await findBundles(projectType);
console.log(`Found ${bundles.length} bundles:`);
bundles.forEach(b => console.log(`  - ${b}`));
```

**Search Patterns:**

**Expo:**
- `dist/_expo/static/js/**/*.js`
- `.expo/static/js/**/*.js`
- `web-build/static/js/**/*.js`

**React Native CLI:**
- `android/app/build/generated/assets/react/**/index.android.bundle`
- `android/app/src/main/assets/index.android.bundle`
- `ios/build/**/main.jsbundle`
- `ios/main.jsbundle`

Files smaller than 10KB are excluded (likely not main bundles).

---

## Types and Interfaces

### `Finding`

Represents a single security finding.

```typescript
interface Finding {
  // Rule identification
  id: string;                 // Rule ID (e.g., 'KEY-OPENAI')
  title: string;              // Short title
  severity: Severity;         // Severity level
  
  // Finding details
  message: string;            // Detailed message
  position: number;           // Character position in bundle
  snippet?: string;           // Code snippet around finding
  match?: string;             // Matched text
  
  // Additional metadata (optional)
  meta?: {
    entropy?: number;         // Shannon entropy (for KEY-OTHER)
    length?: number;          // String length
    [key: string]: any;       // Rule-specific metadata
  };
  
  // Multi-bundle scanning
  bundle?: string;            // Bundle path (for multi-bundle scans)
}
```

### `Severity`

Severity levels for security findings.

```typescript
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
```

**Severity Guidelines:**

| Level | Description | Examples |
|-------|-------------|----------|
| `critical` | Immediate action required | API keys, credentials, private keys |
| `high` | Serious security risk | JWT tokens, SSL bypass, admin passwords |
| `medium` | Moderate risk | HTTP URLs, debug code, AsyncStorage usage |
| `low` | Minor issues | Staging endpoints, dev markers |
| `info` | Informational | Suggestions, best practices |

---

## Advanced Usage

### Custom Security Workflow

```javascript
import { scanBundle } from 'lupin-security-scanner';
import { sendSlackNotification } from './slack.js';
import fs from 'fs';

async function customSecurityAudit(bundlePath) {
  const result = await scanBundle(bundlePath, {
    failLevel: 'critical',
    showLevel: 'info'  // Get all findings
  });

  // Filter by category
  const apiKeyLeaks = result.allFindings.filter(f => 
    f.id.startsWith('KEY-')
  );

  // High-entropy analysis
  const suspiciousStrings = result.allFindings
    .filter(f => f.id === 'KEY-OTHER')
    .filter(f => f.meta?.entropy > 4.5);

  // Generate custom report
  const report = {
    timestamp: new Date().toISOString(),
    bundle: bundlePath,
    summary: {
      total: result.totalFindings,
      critical: result.severityBreakdown.critical || 0,
      apiKeys: apiKeyLeaks.length,
      suspiciousStrings: suspiciousStrings.length
    },
    findings: {
      apiKeys: apiKeyLeaks,
      suspicious: suspiciousStrings
    }
  };

  // Save report
  fs.writeFileSync(
    'security-audit.json',
    JSON.stringify(report, null, 2)
  );

  // Notify team if critical issues
  if (result.severityBreakdown.critical > 0) {
    await sendSlackNotification({
      channel: '#security',
      message: `🚨 ${result.severityBreakdown.critical} critical security issues found in ${bundlePath}`,
      attachments: [{
        findings: apiKeyLeaks.slice(0, 5)  // Show first 5
      }]
    });
  }

  return result;
}
```

### Parallel Bundle Scanning

```javascript
import { scanBundle } from 'lupin-security-scanner';
import { glob } from 'glob';

async function scanAllBundles() {
  // Find all bundles
  const bundles = await glob('dist/**/*.bundle.js');

  // Scan in parallel (with limit)
  const concurrency = 3;
  const results = [];

  for (let i = 0; i < bundles.length; i += concurrency) {
    const batch = bundles.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(b => scanBundle(b))
    );
    results.push(...batchResults);
  }

  // Aggregate results
  const totalFindings = results.reduce(
    (sum, r) => sum + r.totalFindings,
    0
  );

  return { bundles: results, totalFindings };
}
```

### Integration with Build Tools

#### Webpack Plugin

```javascript
// webpack-lupin-plugin.js
import { scanBundle } from 'lupin-security-scanner';

export class LupinWebpackPlugin {
  constructor(options = {}) {
    this.options = options;
  }

  apply(compiler) {
    compiler.hooks.afterEmit.tapPromise('LupinPlugin', async (compilation) => {
      const bundles = Array.from(compilation.assets.keys())
        .filter(f => f.endsWith('.js'))
        .map(f => compilation.outputOptions.path + '/' + f);

      for (const bundle of bundles) {
        const result = await scanBundle(bundle, this.options);
        
        if (result.hasBlockingFindings) {
          compilation.errors.push(
            new Error(`Lupin: Security issues found in ${bundle}`)
          );
        }
      }
    });
  }
}
```

#### Metro Bundler

```javascript
// metro.config.js
import { scanBundle } from 'lupin-security-scanner';

module.exports = {
  serializer: {
    customSerializer: async (entryPoint, preModules, graph, options) => {
      // Default Metro serialization
      const bundle = require('metro/src/lib/bundleToString')(
        baseJSBundle(entryPoint, preModules, graph, options)
      );

      // Scan if production
      if (!options.dev) {
        const tempFile = '/tmp/metro-bundle.js';
        require('fs').writeFileSync(tempFile, bundle.code);
        
        const result = await scanBundle(tempFile, {
          failLevel: 'high'
        });

        if (result.hasBlockingFindings) {
          throw new Error(
            `Security scan failed: ${result.totalFindings} issues found`
          );
        }
      }

      return bundle;
    }
  }
};
```

---

## Error Handling

All functions may throw errors that should be handled:

```javascript
import { scanBundle } from 'lupin-security-scanner';

try {
  const result = await scanBundle('./dist/bundle.js');
  // Process result
} catch (error) {
  if (error.code === 'ENOENT') {
    console.error('Bundle file not found');
  } else if (error.message.includes('Bundle not found')) {
    console.error('Invalid bundle path');
  } else {
    console.error('Scan error:', error.message);
  }
  process.exit(1);
}
```

**Common Errors:**

- `ENOENT` - File not found
- `EISDIR` - Path is a directory, not a file
- `EACCES` - Permission denied
- `Bundle not found` - Invalid path
- `Invalid bundle` - File is not JavaScript

---

## Performance Considerations

### Large Bundles

For bundles >10MB:

```javascript
const result = await scanBundle('./large-bundle.js', {
  maxFindings: 1000  // Limit findings to save memory
});
```

### Memory Usage

Each finding uses ~1KB of memory. For a bundle with 5000 findings:
- Memory usage: ~5MB for findings
- Bundle size: Loaded into memory once
- Peak memory: Bundle size + findings + overhead

### Optimization Tips

1. **Limit findings**: Use `maxFindings` option
2. **Filter early**: Use `showLevel` to reduce results
3. **Parallel limits**: Don't scan too many bundles concurrently
4. **Stream results**: Process findings as they're found (not currently supported)

---

## TypeScript Support

Lupin includes JSDoc type definitions that work with TypeScript:

```typescript
import { scanBundle, type ScanResult, type Finding } from 'lupin-security-scanner';

async function audit(bundlePath: string): Promise<ScanResult> {
  const result = await scanBundle(bundlePath, {
    failLevel: 'high',
    showLevel: 'medium'
  });

  const criticalFindings: Finding[] = result.allFindings.filter(
    (f): f is Finding => f.severity === 'critical'
  );

  return result;
}
```

---

## Next Steps

- [Testing Guide](TESTING.md) - How to test your security workflows
- [Rules Reference](RULES.md) - Complete list of security rules
- [Examples](../examples/) - More usage examples
- [Contributing](../CONTRIBUTING.md) - Add new features or rules

---

**Questions?** Open an issue on [GitHub](https://github.com/yourusername/lupin-security-scanner/issues)

