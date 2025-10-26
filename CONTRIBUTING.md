# Contributing to Lupin Security Scanner

Thank you for your interest in contributing to Lupin! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Adding New Security Rules](#adding-new-security-rules)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Community](#community)

## 📜 Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@yourdomain.com.

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (OS, Node version, npm version)
- **Bundle characteristics** (size, framework, platform)
- **Screenshots or console output** (if applicable)

**Bug Report Template:**

```markdown
**Description**
A clear description of the bug.

**To Reproduce**
1. Create bundle with '...'
2. Run 'lupin --bundle ...'
3. See error

**Expected Behavior**
What should happen.

**Actual Behavior**
What actually happens.

**Environment**
- OS: [e.g., macOS 14.0]
- Node: [e.g., 18.17.0]
- Lupin: [e.g., 1.0.0]
- Project: [Expo/RN CLI]

**Additional Context**
Any other relevant information.
```

### Suggesting Features

Feature suggestions are welcome! Please provide:

- **Clear use case** - Why is this feature needed?
- **Proposed solution** - How should it work?
- **Alternatives considered** - What other approaches did you think about?
- **Additional context** - Screenshots, examples, related projects

### Improving Documentation

Documentation improvements are always appreciated:

- Fix typos or unclear explanations
- Add examples for common use cases
- Improve API documentation
- Translate documentation (if multilingual support is added)
- Write blog posts or tutorials

### Adding Security Rules

New security detection rules are highly valuable! See [Adding New Security Rules](#adding-new-security-rules) below.

## 🛠️ Development Setup

### Prerequisites

- **Node.js** ≥16.0.0
- **npm** ≥7.0.0 or **yarn** ≥1.22.0
- **Git**

### Getting Started

1. **Fork and Clone**

```bash
# Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/lupin-security-scanner.git
cd lupin-security-scanner
```

2. **Install Dependencies**

```bash
npm install
```

3. **Create a Branch**

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

4. **Make Changes**

Edit the code, add tests, update documentation.

5. **Test Your Changes**

```bash
# Run tests
npm test

# Test CLI locally
node bin/lupin.js --help
node bin/lupin.js --bundle test/fixtures/sample-bundle.js

# Test as installed package
npm link
lupin --help
```

6. **Commit Changes**

```bash
git add .
git commit -m "feat: add new security rule for XYZ"
# or
git commit -m "fix: resolve false positive in ABC detection"
```

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `chore:` - Build process, dependencies
- `perf:` - Performance improvements

7. **Push and Create PR**

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## 🔄 Pull Request Process

### Before Submitting

- [ ] Code follows the project's style guidelines
- [ ] Tests pass (`npm test`)
- [ ] New code has test coverage
- [ ] Documentation is updated
- [ ] Commit messages follow conventional commits
- [ ] No linting errors
- [ ] PR description clearly explains changes

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No linting errors
- [ ] Follows coding standards
```

### Review Process

1. **Automated Checks** - CI/CD runs tests and linting
2. **Code Review** - Maintainer reviews code
3. **Feedback** - Address any requested changes
4. **Approval** - Once approved, PR will be merged
5. **Release** - Changes included in next release

## 💻 Coding Standards

### JavaScript Style

- **ES Modules** - Use `import/export`
- **Modern syntax** - ES2020+ features
- **No semicolons** - (optional, be consistent)
- **2 spaces** - For indentation
- **Descriptive names** - Clear variable/function names

### File Organization

```
lupin-security-scanner/
├── bin/
│   └── lupin.js          # CLI entry point
├── src/
│   ├── index.js          # Programmatic API
│   ├── rules/            # Security rules (future)
│   └── utils/            # Utility functions (future)
├── test/
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── fixtures/         # Test bundles
├── docs/                 # Documentation
└── package.json
```

### Code Comments

- Use JSDoc for functions and classes
- Explain "why", not "what"
- Keep comments up-to-date

```javascript
/**
 * Detect secrets using Shannon entropy analysis
 * 
 * Uses information theory to identify high-entropy strings
 * that are likely to be API keys or tokens.
 * 
 * @param {string} str - String to analyze
 * @returns {number} Entropy value (0-8)
 */
function shannonEntropy(str) {
  // Implementation
}
```

## 🔐 Adding New Security Rules

Security rules are the heart of Lupin. Here's how to add new ones:

### Rule Structure

```javascript
{
  id: 'CATEGORY-###',
  title: 'Short descriptive title',
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  run: (code) => {
    // Detection logic
    const findings = [];
    // ... scan code ...
    return findings; // Array of finding objects
  }
}
```

### Rule Categories

- `KEY-*` - API keys and secrets
- `RN-*` - React Native specific
- `NET-*` - Network security
- `DB-*` - Database security
- `CRYPTO-*` - Cryptography
- `AUTH-*` - Authentication
- `PAY-*` - Payment security
- `ENV-*` - Environment/config
- `WV-*` - WebView security
- `ADMIN-*` - Admin/privileged access

### Example: Adding a New API Key Rule

```javascript
{
  id: 'KEY-NEWSERVICE',
  title: 'NewService API Key',
  severity: 'critical',
  run: (code) => findRegex(
    code,
    /newservice_[a-zA-Z0-9]{32}/g,
    'NewService API key detected. Never expose API keys in client code.'
  )
}
```

### Testing New Rules

1. **Create Test Fixture**

```javascript
// test/fixtures/newservice-key.js
const testBundle = `
  const config = {
    apiKey: "newservice_abc123xyz789..." // Should be detected
  };
`;
```

2. **Write Test**

```javascript
// test/unit/rules.test.js
test('detects NewService API key', () => {
  const findings = scanBundle(testBundle);
  expect(findings).toContainEqual(
    expect.objectContaining({
      id: 'KEY-NEWSERVICE',
      severity: 'critical'
    })
  );
});
```

3. **Update Documentation**

Add rule to README.md and docs/RULES.md.

### False Positive Considerations

- Consider context (test files, mock data)
- Balance sensitivity vs false positives
- Provide clear remediation guidance

## 🧪 Testing Guidelines

### Test Structure

```
test/
├── unit/                    # Unit tests
│   ├── rules.test.js       # Rule testing
│   ├── scanner.test.js     # Scanner logic
│   └── utils.test.js       # Utility functions
├── integration/            # Integration tests
│   ├── cli.test.js        # CLI testing
│   └── api.test.js        # Programmatic API
└── fixtures/              # Test bundles
    ├── clean-bundle.js    # No findings
    ├── secrets-bundle.js  # With secrets
    └── ...
```

### Running Tests

```bash
# All tests
npm test

# Watch mode
npm test -- --watch

# Coverage
npm test -- --coverage

# Specific file
npm test -- rules.test.js
```

### Writing Tests

```javascript
import { scanBundle } from '../src/index.js';

describe('OpenAI Key Detection', () => {
  test('detects sk-proj- keys', () => {
    const code = 'const key = "sk-proj-abc123...";';
    const result = scanBundle(code);
    
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('KEY-OPENAI-PROJ');
  });

  test('no false positives on comments', () => {
    const code = '// Example: sk-proj-XXXXX';
    const result = scanBundle(code);
    
    expect(result.findings).toHaveLength(0);
  });
});
```

## 📚 Documentation

### Types of Documentation

1. **README.md** - Overview, quick start, features
2. **API.md** - Detailed API reference
3. **RULES.md** - Complete rule catalog
4. **TESTING.md** - Testing guide for users
5. **CHANGELOG.md** - Version history
6. **Inline comments** - Code documentation

### Documentation Standards

- Use clear, simple language
- Include code examples
- Keep up-to-date with code changes
- Test code examples to ensure they work

### API Documentation Format

```markdown
### `functionName(param1, param2)`

Brief description of what the function does.

**Parameters:**
- `param1` (type): Description
- `param2` (type): Description

**Returns:** Return type and description

**Example:**
\`\`\`javascript
const result = functionName('value1', 'value2');
console.log(result);
\`\`\`
```

## 🌐 Community

### Communication Channels

- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - Questions, ideas, showcase
- **Email** - support@yourdomain.com

### Getting Help

- Check existing issues and discussions
- Read the documentation
- Search for similar problems
- Provide detailed information when asking questions

### Recognition

Contributors will be:

- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in security advisories (if applicable)

## 🏗️ Project Structure

### Key Files

- `bin/lupin.js` - CLI implementation
- `src/index.js` - Programmatic API
- `package.json` - Package configuration
- `RULES` array - Security detection rules

### Future Structure (Planned)

```
src/
├── rules/
│   ├── api-keys.js      # API key rules
│   ├── react-native.js  # RN-specific rules
│   ├── network.js       # Network security
│   └── index.js         # Rule aggregator
├── scanner/
│   ├── engine.js        # Core scanner
│   ├── entropy.js       # Entropy analysis
│   └── dedup.js         # Deduplication
├── reporters/
│   ├── console.js       # CLI output
│   ├── json.js          # JSON reports
│   └── html.js          # HTML reports (future)
└── index.js             # Public API
```

## 📦 Release Process

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v1.x.x`
4. Push tag: `git push origin v1.x.x`
5. GitHub Action builds and publishes to npm
6. Create GitHub Release with notes

## ❓ Questions?

Feel free to:

- Open a [GitHub Discussion](https://github.com/yourusername/lupin-security-scanner/discussions)
- Email us at support@yourdomain.com
- Check existing documentation

## 🙏 Thank You!

Every contribution, no matter how small, makes Lupin better. Thank you for helping make mobile apps more secure!

---

**Happy Coding! 🔒**

