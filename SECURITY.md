# Security Policy

## 🛡️ Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## 🔒 Reporting a Vulnerability

We take the security of Lupin Security Scanner seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please Do NOT:

- Open a public GitHub issue for security vulnerabilities
- Discuss the vulnerability in public forums, social media, or Discord/Slack channels
- Exploit the vulnerability in any way

### Please DO:

**Report security vulnerabilities via email to:** security@yourdomain.com

Include the following information:

1. **Description**: Brief description of the vulnerability
2. **Impact**: What could an attacker do with this vulnerability?
3. **Reproduction**: Step-by-step instructions to reproduce the issue
4. **Version**: Which version(s) are affected?
5. **Your Details** (optional): Name and contact information if you'd like credit

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within **48 hours**
- **Updates**: We will send you regular updates about our progress at least every **5 business days**
- **Resolution Timeline**: We aim to resolve critical vulnerabilities within **7 days**, high severity within **14 days**
- **Disclosure**: We will coordinate with you on the disclosure timeline
- **Credit**: We will credit you in the security advisory (if you wish)

### Severity Classification

We classify vulnerabilities using the following criteria:

#### Critical
- Remote code execution
- Authentication bypass
- Privilege escalation
- Data breach affecting sensitive information

#### High
- Denial of service
- Information disclosure of sensitive data
- Security feature bypass

#### Medium
- Information disclosure of non-sensitive data
- Security misconfiguration

#### Low
- Information exposure with minimal impact
- Security recommendations

## 🔐 Security Measures in Lupin

Lupin is a **static analysis tool** and does not:

- Execute or run the code it analyzes
- Send data to external servers
- Require network access for scanning
- Store scan results remotely (unless explicitly configured)
- Access system resources beyond reading bundle files

### Data Privacy

- **Local Processing**: All scans are performed locally on your machine
- **No Telemetry**: We do not collect usage data or telemetry
- **No External Calls**: Lupin does not make network requests during scanning
- **File Permissions**: Lupin only reads files in specified directories

### Dependencies

We regularly audit our dependencies for known vulnerabilities:

```bash
npm audit
```

Current dependencies:
- `chalk` - Terminal styling (trusted, widely used)
- `commander` - CLI framework (trusted, widely used)
- `glob` - File pattern matching (trusted, widely used)

## 🔍 Security Best Practices for Users

### 1. Verify Package Integrity

Always verify the package signature and checksum:

```bash
npm view lupin-security-scanner integrity
```

### 2. Use Official Sources

Only install from official sources:

```bash
# ✅ Official npm registry
npm install lupin-security-scanner

# ❌ Don't use unofficial sources
```

### 3. Review Permissions

Lupin requires minimal permissions:
- Read access to bundle files
- Write access for JSON reports (if specified)

### 4. Isolate in CI/CD

Run Lupin in isolated CI/CD environments:

```yaml
# Example: GitHub Actions with limited permissions
permissions:
  contents: read
  pull-requests: write
```

### 5. Scan in Sandboxed Environments

For maximum security, run scans in Docker containers:

```dockerfile
FROM node:18-alpine
RUN npm install -g lupin-security-scanner
WORKDIR /scan
CMD ["lupin", "--bundle", "/scan/bundle.js"]
```

### 6. Regular Updates

Keep Lupin updated to get the latest security rules:

```bash
npm update -g lupin-security-scanner
```

### 7. Audit JSON Reports

JSON reports may contain sensitive findings. Handle them securely:

```bash
# Encrypt reports before storage
gpg --encrypt --recipient security@company.com report.json

# Set restrictive permissions
chmod 600 security-report.json
```

## 🚨 Known Security Considerations

### False Positives

Lupin uses pattern matching and may report false positives. Always review findings:

- Public API keys (e.g., Firebase public config) may be flagged
- Test data or mock values may trigger alerts
- Obfuscated code may cause incorrect detections

### False Negatives

Static analysis has limitations:

- Highly obfuscated code may evade detection
- Dynamically constructed strings may not be caught
- New secret patterns may not be recognized

**Recommendation**: Use Lupin as **one layer** in a defense-in-depth strategy, not as the only security measure.

### Bundle Size Limits

Very large bundles (>100MB) may:

- Consume significant memory
- Take longer to scan
- Hit Node.js memory limits

**Mitigation**: Use `--max-findings` option to limit memory usage.

## 📋 Security Checklist for Contributors

If you're contributing to Lupin, ensure:

- [ ] No hardcoded credentials in tests or examples
- [ ] Dependencies are from trusted sources
- [ ] New dependencies are audited (`npm audit`)
- [ ] Code does not execute or eval user input
- [ ] File operations use safe path handling
- [ ] Regex patterns don't cause ReDoS vulnerabilities
- [ ] Error messages don't leak sensitive information
- [ ] Tests don't contain real API keys or secrets

## 🔄 Security Update Process

1. **Vulnerability Reported**: Security team receives report
2. **Triage**: Severity assessment and validation (24-48 hours)
3. **Fix Development**: Develop and test patch
4. **Security Advisory**: Draft GitHub Security Advisory
5. **Release**: Publish patched version
6. **Notification**: Notify users via:
   - GitHub Security Advisory
   - npm security advisory
   - README update
   - Email (if available)

## 📞 Contact

- **Security Issues**: security@yourdomain.com
- **General Support**: support@yourdomain.com
- **GitHub Issues**: https://github.com/yourusername/lupin-security-scanner/issues (non-security bugs only)

## 🏆 Security Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

*No vulnerabilities reported yet*

---

**PGP Key for Security Reports**:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Your PGP public key here if you use PGP]
-----END PGP PUBLIC KEY BLOCK-----
```

---

Last Updated: 2025-10-26

