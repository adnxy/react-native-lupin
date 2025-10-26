# ✅ Pre-Publish Checklist

Use this checklist before publishing to NPM.

---

## 📋 Before Publishing

### 1. Code Quality
- [x] All functionality tested
- [x] No console.log/debug statements
- [x] No hardcoded secrets or API keys
- [x] Code is clean and readable

### 2. Package Configuration
- [x] `package.json` has correct name
- [x] Version number is correct (1.0.0 for first release)
- [x] Description is clear
- [x] Keywords are relevant
- [x] Author name is correct
- [x] License is set (MIT)
- [x] Repository URL is correct
- [x] Bin entry point is correct
- [x] Files array includes only necessary files

### 3. Documentation
- [x] README.md is complete
- [x] QUICK_START.md exists
- [x] CI-CD.md with integration examples
- [x] CHANGELOG.md updated
- [x] LICENSE file exists

### 4. Files & Permissions
- [x] `.npmignore` excludes dev files
- [x] `.gitignore` excludes node_modules
- [x] `bin/lupin.js` is executable (`chmod +x`)
- [x] Shebang line in bin script (`#!/usr/bin/env node`)

### 5. Git
- [x] All changes committed
- [x] Pushed to GitHub
- [x] Remote repository set correctly
- [x] Tags pushed (if any)

---

## 🧪 Testing

### Local Testing

```bash
# Navigate to package directory
cd ~/Desktop/mobile-workspace/lupin-security-scanner

# Link globally
npm link

# Test in another project
cd ~/Desktop/mobile-workspace/onboarding-app
lupin --help
lupin --scan-all

# Unlink when done
npm unlink -g lupin-security-scanner
```

### Verify Package Contents

```bash
cd ~/Desktop/mobile-workspace/lupin-security-scanner

# See what will be published
npm pack --dry-run
```

**Expected output:**
```
npm notice package: lupin-security-scanner@1.0.0
npm notice === Tarball Contents ===
npm notice 48.6kB bin/lupin.js
npm notice 15.2kB README.md
npm notice 1.1kB  LICENSE
npm notice 3.4kB  QUICK_START.md
npm notice 1.2kB  package.json
npm notice === Tarball Details ===
npm notice total files:       5
```

### Create Test Package

```bash
# Create actual tarball
npm pack

# Extract and inspect
tar -xzf lupin-security-scanner-1.0.0.tgz
cd package
ls -la

# Test installation from tarball
npm install -g ./lupin-security-scanner-1.0.0.tgz
lupin --version

# Clean up
cd ..
rm -rf package lupin-security-scanner-*.tgz
npm uninstall -g lupin-security-scanner
```

---

## 🚀 Publishing Steps

### 1. Final Check

```bash
cd ~/Desktop/mobile-workspace/lupin-security-scanner

# Check version
cat package.json | grep '"version"'

# Check for uncommitted changes
git status

# Verify dependencies are installed
npm install
```

### 2. NPM Login

```bash
npm login
```

Enter:
- Username
- Password  
- Email
- OTP (if 2FA enabled)

Verify:
```bash
npm whoami
# Should show: adnxy
```

### 3. Publish!

```bash
npm publish
```

### 4. Verify Published

```bash
# View on NPM (wait 1-2 minutes for indexing)
open https://www.npmjs.com/package/lupin-security-scanner

# Test installation
npx lupin-security-scanner@latest --help
```

---

## 🎯 Post-Publishing

### 1. Tag Release on GitHub

```bash
git tag v1.0.0
git push origin v1.0.0
```

### 2. Create GitHub Release

Go to: https://github.com/adnxy/react-native-lupin/releases/new

- Tag: v1.0.0
- Title: Lupin Security Scanner v1.0.0
- Description: Copy from CHANGELOG.md

### 3. Announce

- [ ] Tweet about it
- [ ] Post on Reddit (r/reactnative)
- [ ] Share in React Native Discord
- [ ] Post on LinkedIn
- [ ] Add to React Native Community libraries

### 4. Update README Badges

Add to README.md:
```markdown
[![npm version](https://img.shields.io/npm/v/lupin-security-scanner.svg)](https://www.npmjs.com/package/lupin-security-scanner)
[![npm downloads](https://img.shields.io/npm/dm/lupin-security-scanner.svg)](https://www.npmjs.com/package/lupin-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

---

## 🔍 Quick Commands

```bash
# Pre-publish checks
npm pack --dry-run
npm test
git status

# Publishing
npm login
npm publish

# Post-publish
git tag v1.0.0
git push --tags
```

---

## ⚠️ Common Issues & Solutions

### "You do not have permission"
**Cause**: Package name already taken  
**Solution**: Change package name in package.json or use scoped package:
```json
{
  "name": "@adnxy/lupin-security-scanner"
}
```

### "Version already published"
**Cause**: 1.0.0 already exists  
**Solution**: Bump version:
```bash
npm version patch  # 1.0.1
```

### "ENEEDAUTH"
**Cause**: Not logged in  
**Solution**:
```bash
npm logout
npm login
```

### "Package size too large"
**Cause**: Including unnecessary files  
**Solution**: Check .npmignore and package.json "files"

---

## 📊 After 1-2 Days

### Check Stats

```bash
# View downloads
npm info lupin-security-scanner

# Check NPM page
open https://www.npmjs.com/package/lupin-security-scanner
```

### Monitor

- GitHub issues
- NPM download count
- User feedback
- Security vulnerabilities (npm audit)

---

## 🔄 Future Updates

When releasing updates:

```bash
# 1. Make changes and commit
git add .
git commit -m "feat: new feature"

# 2. Bump version
npm version minor  # or patch/major

# 3. Update CHANGELOG.md
# (manual step)

# 4. Push
git push origin main --tags

# 5. Publish
npm publish

# 6. Create GitHub release
# (manual step)
```

---

## ✨ You're Ready!

If all items above are checked, you can publish with confidence! 🚀

Run:
```bash
npm publish
```

---

**Good luck! 🎉**

