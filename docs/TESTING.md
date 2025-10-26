# Testing Guide

Learn how to test your React Native and Expo applications with Lupin Security Scanner.

## Table of Contents

- [Quick Start](#quick-start)
- [Testing Workflows](#testing-workflows)
- [CI/CD Integration](#cicd-integration)
- [Local Development](#local-development)
- [Automated Testing](#automated-testing)
- [False Positives](#handling-false-positives)
- [Best Practices](#best-practices)

---

## Quick Start

### 1. Build Your Bundle

**Expo:**
```bash
# Production iOS bundle
npx expo export --platform ios

# Production Android bundle
npx expo export --platform android

# All platforms
npx expo export
```

**React Native CLI:**
```bash
# iOS bundle
npx react-native bundle \
  --platform ios \
  --dev false \
  --entry-file index.js \
  --bundle-output ios/main.jsbundle \
  --assets-dest ios

# Android bundle
npx react-native bundle \
  --platform android \
  --dev false \
  --entry-file index.js \
  --bundle-output android/app/src/main/assets/index.android.bundle \
  --assets-dest android/app/src/main/res
```

### 2. Run Lupin

```bash
# Auto-detect and scan
lupin

# Or scan specific bundle
lupin --bundle ./dist/_expo/static/js/ios/entry-abc123.js
```

---

## Testing Workflows

### Pre-Release Testing

Test before every release to catch issues early:

```bash
# Add to package.json
{
  "scripts": {
    "build:ios": "npx expo export --platform ios",
    "build:android": "npx expo export --platform android",
    "security:ios": "npm run build:ios && lupin --type expo --fail-level high",
    "security:android": "npm run build:android && lupin --type expo --fail-level high",
    "security": "npm run build:ios && npm run build:android && lupin --scan-all --fail-level high",
    "prerelease": "npm run security"
  }
}
```

Then before releasing:

```bash
npm run prerelease
```

### Development Testing

Quick security checks during development:

```bash
# Lower threshold for development
lupin --show-level medium --fail-level critical

# Or just informational
lupin --show-level info --fail-level critical
```

### Staging Testing

Comprehensive testing before production:

```bash
lupin --scan-all --fail-level high --json staging-security-report.json
```

### Production Testing

Strict testing for production bundles:

```bash
lupin --scan-all --fail-level medium --json production-security-report.json
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]
  schedule:
    # Run daily at 2 AM
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build iOS bundle
        run: npx expo export --platform ios
        env:
          NODE_ENV: production

      - name: Build Android bundle
        run: npx expo export --platform android
        env:
          NODE_ENV: production

      - name: Install Lupin
        run: npm install -g lupin-security-scanner

      - name: Run security scan
        id: scan
        run: |
          lupin --scan-all \
            --fail-level high \
            --json security-report.json \
            --no-color
        continue-on-error: true

      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
          retention-days: 30

      - name: Comment PR with results
        if: github.event_name == 'pull_request' && steps.scan.outcome == 'failure'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
            
            const comment = `## 🔒 Security Scan Results
            
            **Status:** ❌ Failed
            **Total Findings:** ${report.totalFindings}
            **Critical:** ${report.summary.severityBreakdown.critical || 0}
            **High:** ${report.summary.severityBreakdown.high || 0}
            **Medium:** ${report.summary.severityBreakdown.medium || 0}
            
            Please review the [security report](../actions/runs/${{ github.run_id }}) and address critical/high severity issues.
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });

      - name: Fail if security issues found
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - security

variables:
  NODE_VERSION: "18"

build:
  stage: build
  image: node:${NODE_VERSION}
  cache:
    paths:
      - node_modules/
  script:
    - npm ci
    - npx expo export --platform ios
    - npx expo export --platform android
  artifacts:
    paths:
      - dist/
    expire_in: 1 day

security_scan:
  stage: security
  image: node:${NODE_VERSION}
  dependencies:
    - build
  script:
    - npm install -g lupin-security-scanner
    - lupin --scan-all --fail-level high --json security-report.json
  artifacts:
    reports:
      paths:
        - security-report.json
    when: always
    expire_in: 30 days
  allow_failure: false

security_scan_nightly:
  extends: security_scan
  only:
    - schedules
  variables:
    FAIL_LEVEL: "medium"
```

### CircleCI

Create `.circleci/config.yml`:

```yaml
version: 2.1

orbs:
  node: circleci/node@5.1.0

jobs:
  security-scan:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - node/install-packages
      
      - run:
          name: Build bundles
          command: |
            npx expo export --platform ios
            npx expo export --platform android

      - run:
          name: Install Lupin
          command: npm install -g lupin-security-scanner

      - run:
          name: Run security scan
          command: |
            lupin --scan-all \
              --fail-level high \
              --json security-report.json
      
      - store_artifacts:
          path: security-report.json
          destination: security-reports

      - store_test_results:
          path: security-report.json

workflows:
  version: 2
  build-and-scan:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
```

### Jenkins

Create `Jenkinsfile`:

```groovy
pipeline {
    agent {
        docker {
            image 'node:18'
        }
    }
    
    environment {
        NODE_ENV = 'production'
    }
    
    stages {
        stage('Install') {
            steps {
                sh 'npm ci'
            }
        }
        
        stage('Build Bundles') {
            parallel {
                stage('iOS') {
                    steps {
                        sh 'npx expo export --platform ios'
                    }
                }
                stage('Android') {
                    steps {
                        sh 'npx expo export --platform android'
                    }
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'npm install -g lupin-security-scanner'
                sh 'lupin --scan-all --fail-level high --json security-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json', fingerprint: true
                }
            }
        }
    }
    
    post {
        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "Security issues found. Check the build logs and security report.",
                to: "security@company.com"
            )
        }
    }
}
```

---

## Local Development

### Pre-commit Hook

Automatically scan before commits:

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔒 Running Lupin security scan..."

# Build latest bundle (adjust for your project)
npm run build:ios > /dev/null 2>&1 || {
  echo "⚠️  Failed to build bundle"
  exit 1
}

# Run scan (fail only on critical)
lupin --scan-all --fail-level critical --no-color

if [ $? -ne 0 ]; then
  echo "⛔ Critical security issues found!"
  echo "Fix issues or use 'git commit --no-verify' to skip (not recommended)"
  exit 1
fi

echo "✅ Security scan passed!"
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### VS Code Task

Create `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "lupin",
      "args": [
        "--scan-all",
        "--fail-level", "high",
        "--json", "security-report.json"
      ],
      "group": {
        "kind": "test",
        "isDefault": false
      },
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": true,
        "panel": "dedicated"
      },
      "problemMatcher": []
    },
    {
      "label": "Quick Security Check",
      "type": "shell",
      "command": "lupin",
      "args": [
        "--fail-level", "critical",
        "--show-level", "high"
      ],
      "group": {
        "kind": "test",
        "isDefault": true
      }
    }
  ]
}
```

Run with: `Cmd/Ctrl + Shift + P` → `Tasks: Run Task` → `Security Scan`

---

## Automated Testing

### Jest Integration

```javascript
// __tests__/security.test.js
import { scanBundle, detectProjectType, findBundles } from 'lupin-security-scanner';
import { execSync } from 'child_process';
import fs from 'fs';

describe('Security Tests', () => {
  beforeAll(() => {
    // Build bundles before testing
    console.log('Building test bundles...');
    execSync('npx expo export --platform ios', { stdio: 'inherit' });
  });

  test('Bundle has no critical security issues', async () => {
    const projectType = detectProjectType();
    const bundles = await findBundles(projectType);
    
    expect(bundles.length).toBeGreaterThan(0);
    
    for (const bundle of bundles) {
      const result = await scanBundle(bundle, {
        failLevel: 'critical'
      });
      
      expect(result.severityBreakdown.critical || 0).toBe(0);
    }
  });

  test('No API keys in production bundle', async () => {
    const projectType = detectProjectType();
    const bundles = await findBundles(projectType);
    
    for (const bundle of bundles) {
      const result = await scanBundle(bundle);
      
      const apiKeyFindings = result.allFindings.filter(f =>
        f.id.startsWith('KEY-')
      );
      
      expect(apiKeyFindings).toHaveLength(0);
    }
  });

  test('Security report is generated', async () => {
    const projectType = detectProjectType();
    const bundles = await findBundles(projectType);
    
    const result = await scanBundle(bundles[0], {
      showLevel: 'info'
    });
    
    const report = {
      timestamp: new Date().toISOString(),
      findings: result.totalFindings,
      critical: result.severityBreakdown.critical || 0
    };
    
    fs.writeFileSync(
      'test-security-report.json',
      JSON.stringify(report, null, 2)
    );
    
    expect(fs.existsSync('test-security-report.json')).toBe(true);
  });
});
```

Run with:

```bash
npm test -- security.test.js
```

### Detox Integration

```javascript
// e2e/security.e2e.js
import { device, expect, element, by } from 'detox';
import { scanBundle } from 'lupin-security-scanner';

describe('Security E2E Tests', () => {
  beforeAll(async () => {
    await device.launchApp();
  });

  it('should have secure bundle in installed app', async () => {
    // Get bundle from installed app (platform-specific)
    const bundlePath = device.getPlatform() === 'ios'
      ? 'ios/build/Build/Products/Release-iphonesimulator/YourApp.app/main.jsbundle'
      : 'android/app/build/outputs/bundle/release/app-release.aab';
    
    // Note: This requires extracting bundle from package
    // Implementation depends on platform
  });
});
```

---

## Handling False Positives

### Documenting Exceptions

Create a whitelist file:

```javascript
// security-whitelist.js
/**
 * Security Finding Whitelist
 * 
 * Document all intentional "violations" here with:
 * - Finding ID
 * - Reason for exception
 * - Date approved
 * - Approver
 */

export const whitelist = [
  {
    id: 'KEY-FIREBASE',
    reason: 'Public Firebase config - protected by security rules',
    approved: '2025-10-26',
    approver: 'security-team@company.com',
    pattern: 'AIzaSyC...' // First few chars for identification
  },
  {
    id: 'KEY-SENTRY',
    reason: 'Public Sentry DSN - designed for client-side use',
    approved: '2025-10-26',
    approver: 'devops@company.com'
  }
];
```

### Custom Filtering

```javascript
// filter-findings.js
import { scanBundle } from 'lupin-security-scanner';
import { whitelist } from './security-whitelist.js';

async function filteredScan(bundlePath) {
  const result = await scanBundle(bundlePath);
  
  // Filter out whitelisted findings
  const filtered = result.allFindings.filter(finding => {
    return !whitelist.some(w =>
      w.id === finding.id &&
      (!w.pattern || finding.match?.includes(w.pattern))
    );
  });
  
  return {
    ...result,
    allFindings: filtered,
    totalFindings: filtered.length,
    whitelisted: result.totalFindings - filtered.length
  };
}
```

---

## Best Practices

### 1. Test Early and Often

```bash
# Daily automated scans
npm run security

# Before every PR
npm run security:pr

# Before every release
npm run security:release
```

### 2. Use Appropriate Fail Levels

```bash
# Development - allow more findings
FAIL_LEVEL=critical npm run security

# Staging - stricter
FAIL_LEVEL=high npm run security

# Production - strictest
FAIL_LEVEL=medium npm run security
```

### 3. Track Findings Over Time

```javascript
// track-security.js
import { scanBundle } from 'lupin-security-scanner';
import fs from 'fs';

async function trackSecurity() {
  const result = await scanBundle('./dist/bundle.js');
  
  const history = JSON.parse(
    fs.readFileSync('security-history.json', 'utf8')
  );
  
  history.push({
    date: new Date().toISOString(),
    commit: process.env.GIT_COMMIT,
    findings: result.totalFindings,
    breakdown: result.severityBreakdown
  });
  
  fs.writeFileSync(
    'security-history.json',
    JSON.stringify(history, null, 2)
  );
}
```

### 4. Automate Report Distribution

```javascript
// notify-team.js
import { scanBundle } from 'lupin-security-scanner';
import nodemailer from 'nodemailer';

async function notifyTeam() {
  const result = await scanBundle('./dist/bundle.js');
  
  if (result.hasBlockingFindings) {
    const transporter = nodemailer.createTransporter(/* config */);
    
    await transporter.sendMail({
      to: 'security@company.com',
      subject: `🚨 Security Issues Found`,
      html: `
        <h2>Security Scan Results</h2>
        <p>Critical: ${result.severityBreakdown.critical || 0}</p>
        <p>High: ${result.severityBreakdown.high || 0}</p>
        <p>Please review immediately.</p>
      `
    });
  }
}
```

### 5. Regular Baseline Updates

```bash
# Generate baseline
lupin --json baseline-security.json

# Compare against baseline
# (custom script to compare reports)
```

---

## Troubleshooting

### Bundle Not Found

```bash
# Verify bundle exists
ls -lh dist/_expo/static/js/**/*.js

# Check project type detection
lupin --type expo  # or --type rn-cli
```

### False Positives

Review findings and add to whitelist if legitimate:

```bash
# Show all findings with context
lupin --show-level info --json full-report.json

# Review the JSON file
cat full-report.json | jq '.findings[] | select(.severity == "critical")'
```

### Memory Issues

For large bundles:

```bash
# Limit findings
lupin --max-findings 1000

# Or increase Node memory
NODE_OPTIONS="--max-old-space-size=4096" lupin
```

---

## Next Steps

- [API Documentation](API.md) - Programmatic usage
- [Rules Reference](RULES.md) - All security rules
- [Contributing](../CONTRIBUTING.md) - Add new rules or features

---

**Questions?** Open an issue on [GitHub](https://github.com/yourusername/lupin-security-scanner/issues)

