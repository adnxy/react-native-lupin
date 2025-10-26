# 📦 Publishing to NPM

Complete guide to publishing Lupin Security Scanner to NPM.

---

## ✅ Pre-Publishing Checklist

Before publishing, make sure:

- [ ] All code is committed to git
- [ ] Tests pass (if applicable)
- [ ] README.md is complete
- [ ] Version number is correct in package.json
- [ ] LICENSE file exists
- [ ] No sensitive data in code
- [ ] .npmignore or package.json "files" is configured
- [ ] Bin scripts are executable (`chmod +x bin/lupin.js`)

---

## 🚀 First Time Setup

### 1. Create NPM Account

If you don't have an NPM account:

```bash
# Visit https://www.npmjs.com/signup
# Or create via CLI
npm adduser
```

### 2. Login to NPM

```bash
npm login
```

You'll be prompted for:
- Username
- Password
- Email
- One-time password (if 2FA enabled)

### 3. Verify Login

```bash
npm whoami
```

Should show your username.

---

## 📋 Prepare for Publishing

### Step 1: Clean Up

```bash
cd ~/Desktop/mobile-workspace/lupin-security-scanner

# Remove unnecessary files
rm -rf node_modules dist test coverage .DS_Store

# Fresh install
npm install
```

### Step 2: Test Locally

```bash
# Link package globally
npm link

# Test in another project
cd ~/Desktop/mobile-workspace/onboarding-app
lupin

# If it works, unlink
npm unlink -g lupin-security-scanner
```

### Step 3: Verify Package Contents

```bash
# See what will be published
npm pack --dry-run

# This shows all files that will be included
```

Should only include:
```
bin/lupin.js
README.md
LICENSE
QUICK_START.md
package.json
```

### Step 4: Check Package

```bash
# Create actual tarball
npm pack

# Extract and inspect
tar -xzf lupin-security-scanner-1.0.0.tgz
ls -la package/

# Clean up
rm -rf package/ lupin-security-scanner-*.tgz
```

---

## 🎯 Publishing

### First Release (v1.0.0)

```bash
# Make sure you're in the right directory
cd ~/Desktop/mobile-workspace/lupin-security-scanner

# Verify version
cat package.json | grep version

# Publish!
npm publish
```

You should see:
```
npm notice 📦  lupin-security-scanner@1.0.0
npm notice === Tarball Contents ===
npm notice 41.5kB bin/lupin.js
npm notice 12.3kB README.md
npm notice ...
npm notice === Tarball Details ===
npm notice package size:  XX.X kB
npm notice unpacked size: XX.X kB
npm notice total files:   X
+ lupin-security-scanner@1.0.0
```

### Verify Published Package

```bash
# View on NPM
open https://www.npmjs.com/package/lupin-security-scanner

# Install and test
npx lupin-security-scanner@latest --help
```

---

## 🔄 Future Updates

### Semantic Versioning

Use semantic versioning (semver):

- **Patch** (1.0.0 → 1.0.1): Bug fixes
- **Minor** (1.0.0 → 1.1.0): New features (backward compatible)
- **Major** (1.0.0 → 2.0.0): Breaking changes

### Update Version

```bash
# Patch release (bug fix)
npm version patch

# Minor release (new feature)
npm version minor

# Major release (breaking change)
npm version major
```

This will:
1. Update `package.json`
2. Create a git commit
3. Create a git tag

### Publish Update

```bash
# Commit any changes first
git add .
git commit -m "feat: add new security rules"

# Update version
npm version minor
# This creates: v1.1.0

# Push to GitHub
git push
git push --tags

# Publish to NPM
npm publish
```

---

## 📝 Publishing Workflow

### Complete Workflow for Updates

```bash
# 1. Make changes
git add .
git commit -m "feat: new AI key detection"

# 2. Update version
npm version minor  # or patch/major

# 3. Update CHANGELOG.md
echo "## [1.1.0] - 2025-10-26
- Added: New AI service detection
- Fixed: Memory leak in scanner
" >> CHANGELOG.md

git add CHANGELOG.md
git commit --amend --no-edit

# 4. Push to GitHub
git push origin main --tags

# 5. Publish to NPM
npm publish

# 6. Verify
npx lupin-security-scanner@latest --version
```

---

## 🏷️ Publishing with Tags

### Latest (Default)

```bash
npm publish
# Installs with: npm install lupin-security-scanner
```

### Beta/Next

```bash
# Update version to beta
npm version 1.1.0-beta.0

# Publish with tag
npm publish --tag beta

# Users install with:
npm install lupin-security-scanner@beta
```

### Legacy Versions

```bash
# Keep old major version available
npm publish --tag legacy-v1
```

---

## ⚠️ Common Issues

### Issue: "You do not have permission to publish"

**Solution**: Package name is taken. Change in `package.json`:

```json
{
  "name": "@your-username/lupin-security-scanner"
}
```

Then:
```bash
npm publish --access public
```

### Issue: "Version already exists"

**Solution**: Update version number:

```bash
npm version patch
npm publish
```

### Issue: "ENEEDAUTH"

**Solution**: Login again:

```bash
npm logout
npm login
```

### Issue: "Package size too large"

**Solution**: Add `.npmignore`:

```
node_modules/
test/
.git/
*.log
.DS_Store
coverage/
.github/
```

---

## 🔐 Security Best Practices

### 1. Enable 2FA

```bash
npm profile enable-2fa auth-and-writes
```

### 2. Use Automation Tokens for CI

```bash
npm token create --read-only
```

Add to GitHub Secrets: `NPM_TOKEN`

### 3. Review Before Publishing

```bash
# Always review what will be published
npm pack --dry-run
```

---

## 🤖 Automate Publishing with GitHub Actions

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to NPM

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      
      - run: npm ci
      
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

**Workflow:**
1. Make changes locally
2. Run `npm version minor`
3. Push: `git push --tags`
4. GitHub Actions automatically publishes! 🚀

---

## 📊 After Publishing

### 1. Add NPM Badge to README

```markdown
[![npm version](https://img.shields.io/npm/v/lupin-security-scanner.svg)](https://www.npmjs.com/package/lupin-security-scanner)
[![npm downloads](https://img.shields.io/npm/dm/lupin-security-scanner.svg)](https://www.npmjs.com/package/lupin-security-scanner)
```

### 2. Announce

- Tweet about it
- Post on Reddit (r/reactnative, r/expo)
- Share on LinkedIn
- Post in React Native Discord/Slack

### 3. Monitor

```bash
# Check download stats
npm info lupin-security-scanner

# View on NPM
open https://www.npmjs.com/package/lupin-security-scanner
```

---

## 🎯 Quick Reference

### Publish First Version
```bash
npm login
npm publish
```

### Update & Republish
```bash
git commit -am "feat: updates"
npm version minor
git push --tags
npm publish
```

### Unpublish (within 72 hours)
```bash
npm unpublish lupin-security-scanner@1.0.0
```

⚠️ **Warning**: Unpublishing is discouraged! Consider deprecating instead:

```bash
npm deprecate lupin-security-scanner@1.0.0 "Use version 1.0.1 instead"
```

---

## ✅ You're Ready!

Your package is now on NPM! 🎉

Users can install with:
```bash
npm install -g lupin-security-scanner
```

**Next steps:**
- Monitor issues on GitHub
- Respond to feedback
- Plan future releases
- Keep dependencies updated

---

**Questions?** [Open an issue](https://github.com/adnxy/react-native-lupin/issues) 📦

