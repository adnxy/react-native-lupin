# Test Fixtures

⚠️ **These files contain INTENTIONAL FAKE secrets for testing purposes only.**

## Purpose

These test bundles are used to verify that the Lupin security scanner correctly detects various security issues. They contain:

- **Fake API keys** that match real patterns but are invalid
- **Simulated vulnerabilities** for testing detection rules
- **Test data** that should never be used in production

## Important Notes

1. **All secrets in these files are FAKE** - They will not work with any real service
2. **These are test fixtures** - Not real code or bundles from actual applications
3. **For testing only** - Used to verify scanner functionality

## Files

- `sample-clean-bundle.js` - A clean bundle with no security issues (should produce zero findings)
- `sample-vulnerable-bundle.js` - A bundle with intentional security issues (should detect 20+ findings)

## GitHub Secret Scanning

If GitHub flags these files during push, it's a false positive. The secrets are:
- Clearly marked as test data in comments
- Modified to be obviously fake (e.g., "FAKE", "TEST", "NOTREAL")
- Configured in `.gitattributes` to be excluded from secret scanning

## For Maintainers

When adding new test cases:
1. Use obviously fake values (include "FAKE", "TEST", "EXAMPLE" in the string)
2. Add clear comments marking the data as test fixtures
3. Never use real secrets, even if they're expired
4. Document the expected behavior in the test file

