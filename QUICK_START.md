# 🚀 Lupin Quick Start

Get started in 2 minutes!

---

## Step 1: Install

```bash
npm install -g react-native-lupin
```

---

## Step 2: Build Your Bundle

### Expo
```bash
npx expo export
```

### React Native CLI
```bash
# Android
cd android && ./gradlew bundleRelease

# iOS  
npx react-native bundle --platform ios --dev false \
  --entry-file index.js --bundle-output ios/main.jsbundle
```

---

## Step 3: Scan

```bash
lupin
```

**That's it!** 🎉

---

## What You'll See

```
╔═══════════════════════════════════════════════╗
║      🔒 LUPIN - Bundle Security Scanner       ║
╚═══════════════════════════════════════════════╝

✓ Detected project type: expo
✓ Found 1 bundle file(s)

🔍 Running security scan...
████████████████████████████████ 100%

📊 Total Findings: 184

Severity Breakdown:
┌────────────────────────────────┐
│  CRITICAL  1                   │
│  HIGH      8                   │
│  MEDIUM    175                 │
└────────────────────────────────┘
```

---

## Common Commands

```bash
# Show only critical issues
lupin --show-level critical

# Export JSON report
lupin --json security-report.json

# CI/CD mode
lupin --scan-all --fail-level high

# Help
lupin --help
```

---

## What It Detects

- 🤖 AI API keys (OpenAI, Claude, Gemini)
- 🔑 Secrets (Stripe, AWS, GitHub)
- 📱 Mobile security issues
- 💳 Payment card data
- 🔓 Insecure code patterns

**60+ security rules!**

---

## Next Steps

- Read the [full README](./README.md)
- Check [security rules](./docs/SECURITY-RULES.md)
- Integrate into [CI/CD](./README.md#cicd-pipeline)

---

**Happy scanning! 🔒**
