# 🚀 CI/CD Integration Guide

Integrate Lupin Security Scanner into your continuous integration pipelines.

---

## 📋 Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Expo EAS Build](#expo-eas-build)
- [CircleCI](#circleci)
- [Bitrise](#bitrise)
- [General Tips](#general-tips)

---

## GitHub Actions

### Basic Setup

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build bundle (Expo)
        run: npx expo export
      
      - name: Run security scan
        run: npx lupin-security-scanner --scan-all --fail-level high --json lupin-report.json
      
      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: lupin-report.json
```

### Advanced: PR Comments

```yaml
name: Security Scan with PR Comments

on:
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install & Build
        run: |
          npm ci
          npx expo export
      
      - name: Security Scan
        id: scan
        continue-on-error: true
        run: |
          npx lupin-security-scanner --scan-all --fail-level high --json report.json --no-color > scan-output.txt || true
          cat scan-output.txt
      
      - name: Comment PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('report.json', 'utf8'));
            const critical = report.summary.severityBreakdown.critical || 0;
            const high = report.summary.severityBreakdown.high || 0;
            
            const comment = `## 🔒 Security Scan Results
            
            - 🔴 Critical: ${critical}
            - 🟠 High: ${high}
            - 🟡 Medium: ${report.summary.severityBreakdown.medium || 0}
            
            ${critical + high > 0 ? '⚠️ Action required!' : '✅ No critical issues found'}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### React Native CLI

```yaml
- name: Build Android bundle
  run: |
    cd android
    ./gradlew bundleRelease

- name: Run security scan
  run: npx lupin-security-scanner --type rn-cli --fail-level high
```

---

## GitLab CI

### Basic Setup

Create `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - security

variables:
  NODE_VERSION: "18"

build:
  stage: build
  image: node:${NODE_VERSION}
  script:
    - npm ci
    - npx expo export
  artifacts:
    paths:
      - dist/
    expire_in: 1 hour

security-scan:
  stage: security
  image: node:${NODE_VERSION}
  dependencies:
    - build
  script:
    - npx lupin-security-scanner --scan-all --fail-level high --json lupin-report.json
  artifacts:
    reports:
      # GitLab can display JSON reports
      codequality: lupin-report.json
    paths:
      - lupin-report.json
    expire_in: 30 days
  allow_failure: false
```

### With Merge Request Integration

```yaml
security-scan:
  stage: security
  image: node:18
  script:
    - npx lupin-security-scanner --scan-all --fail-level high --json report.json --no-color > scan.txt || true
    - cat scan.txt
    
    # Post comment to MR (if using GitLab API)
    - |
      CRITICAL=$(jq '.summary.severityBreakdown.critical // 0' report.json)
      HIGH=$(jq '.summary.severityBreakdown.high // 0' report.json)
      
      if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
        echo "⚠️ Security issues found: $CRITICAL critical, $HIGH high"
        exit 1
      fi
  artifacts:
    reports:
      codequality: report.json
    when: always
```

### For React Native CLI

```yaml
build-android:
  stage: build
  image: reactnativecommunity/react-native-android:latest
  script:
    - cd android
    - ./gradlew bundleRelease
  artifacts:
    paths:
      - android/app/build/generated/assets/
    expire_in: 1 hour

security-scan:
  stage: security
  image: node:18
  dependencies:
    - build-android
  script:
    - npx lupin-security-scanner --type rn-cli --fail-level high
```

---

## Expo EAS Build

### With EAS Hooks

Create `eas.json`:

```json
{
  "build": {
    "production": {
      "node": "18",
      "env": {
        "FAIL_ON_SECURITY_ISSUES": "true"
      }
    },
    "preview": {
      "node": "18"
    }
  },
  "submit": {}
}
```

Create `eas-hooks/post-export.sh`:

```bash
#!/bin/bash

echo "🔒 Running security scan..."

npx lupin-security-scanner --scan-all --fail-level high --json lupin-report.json

if [ $? -ne 0 ]; then
  echo "❌ Security scan failed!"
  if [ "$FAIL_ON_SECURITY_ISSUES" = "true" ]; then
    exit 1
  fi
fi

echo "✅ Security scan complete"
```

Make it executable:
```bash
chmod +x eas-hooks/post-export.sh
```

Update `eas.json` to use hooks:

```json
{
  "build": {
    "production": {
      "hooks": {
        "postExport": "./eas-hooks/post-export.sh"
      }
    }
  }
}
```

### EAS Build with GitHub Actions

```yaml
name: EAS Build + Security

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-node@v3
        with:
          node-version: 18
      
      - name: Setup Expo
        uses: expo/expo-github-action@v8
        with:
          expo-version: latest
          eas-version: latest
          token: ${{ secrets.EXPO_TOKEN }}
      
      - run: npm ci
      
      - name: Export for scanning
        run: npx expo export
      
      - name: Security Scan
        run: npx lupin-security-scanner --scan-all --fail-level high
      
      - name: Build on EAS
        if: success()
        run: eas build --platform all --non-interactive --no-wait
```

---

## CircleCI

Create `.circleci/config.yml`:

```yaml
version: 2.1

orbs:
  node: circleci/node@5.1

jobs:
  security-scan:
    docker:
      - image: cimg/node:18.17
    
    steps:
      - checkout
      
      - node/install-packages:
          pkg-manager: npm
      
      - run:
          name: Export bundle
          command: npx expo export
      
      - run:
          name: Security scan
          command: npx lupin-security-scanner --scan-all --fail-level high --json report.json
      
      - store_artifacts:
          path: report.json
          destination: security-reports

workflows:
  build-and-scan:
    jobs:
      - security-scan
```

---

## Bitrise

Add a Script step in your `bitrise.yml`:

```yaml
- script@1:
    title: Security Scan
    inputs:
      - content: |
          #!/usr/bin/env bash
          set -ex
          
          # Export bundle (Expo)
          npx expo export
          
          # Run security scan
          npx lupin-security-scanner --scan-all --fail-level high --json $BITRISE_DEPLOY_DIR/lupin-report.json
          
          # Upload report
          envman add --key SECURITY_REPORT_PATH --value "$BITRISE_DEPLOY_DIR/lupin-report.json"
```

---

## General Tips

### 1. **Fail Levels**

Choose appropriate fail levels for different scenarios:

```bash
# Strict (production)
--fail-level critical

# Recommended (staging/pre-production)
--fail-level high

# Permissive (development)
--fail-level medium
```

### 2. **Caching**

Speed up CI by caching node_modules:

**GitHub Actions:**
```yaml
- uses: actions/setup-node@v3
  with:
    node-version: 18
    cache: 'npm'
```

**GitLab CI:**
```yaml
cache:
  paths:
    - node_modules/
```

### 3. **Branch-specific Rules**

```yaml
# GitHub Actions
on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

# GitLab CI
rules:
  - if: '$CI_COMMIT_BRANCH == "main"'
  - if: '$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"'
```

### 4. **Skip on Draft PRs**

```yaml
# GitHub Actions
if: github.event.pull_request.draft == false
```

### 5. **Parallel Jobs**

Run security scan in parallel with tests:

```yaml
jobs:
  test:
    # ... run tests
  
  security:
    # ... run security scan
  
  # Both run at the same time!
```

### 6. **Only Scan on Bundle Changes**

```yaml
# GitHub Actions
on:
  push:
    paths:
      - 'src/**'
      - 'app/**'
      - 'package.json'
```

### 7. **Environment-specific Scans**

```bash
# Development: Show all issues
lupin --show-level info

# Staging: Fail on high+
lupin --fail-level high

# Production: Fail on critical only
lupin --fail-level critical
```

---

## Troubleshooting

### Issue: "No bundles found"

Make sure you export/build before scanning:

```bash
# Expo
npx expo export

# React Native CLI
cd android && ./gradlew bundleRelease
```

### Issue: "Too many findings"

Limit findings or increase threshold:

```bash
lupin --max-findings 1000 --show-level high
```

### Issue: CI runs out of memory

Use smaller Node.js Docker images:

```yaml
# Instead of
image: node:18

# Use
image: node:18-alpine
```

---

## Example Workflows

### Simple (Quick Start)

```yaml
- run: npm ci
- run: npx expo export
- run: npx lupin-security-scanner
```

### Production-Ready

```yaml
- run: npm ci
- run: npx expo export
- run: npx lupin-security-scanner --scan-all --fail-level high --json report.json
- uses: actions/upload-artifact@v3
  if: always()
  with:
    name: security-report
    path: report.json
```

### Enterprise (with notifications)

```yaml
- run: npx lupin-security-scanner --scan-all --fail-level critical --json report.json || true
- run: |
    curl -X POST $SLACK_WEBHOOK \
      -d "Security scan completed: $(jq '.summary.total' report.json) findings"
```

---

**Need help?** [Open an issue](https://github.com/adnxy/react-native-lupin/issues) 🔒

