/**
 * Shared scanning utilities and helper functions
 */

export function shannonEntropy(str) {
  // Basic entropy detection for secrets (works on minified bundles too)
  const map = new Map();
  for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
  const len = str.length || 1;
  let ent = 0;
  for (const [, count] of map) {
    const p = count / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function maybeBase64ish(s) {
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

export function maybeHexish(s) {
  return /^[a-f0-9]+$/i.test(s);
}

export function findRegex(code, regex, message) {
  const results = [];
  let m;
  while ((m = regex.exec(code))) {
    results.push(makeFinding(message, m.index, code, m[0]));
  }
  return results;
}

export function makeFinding(message, idx, code, matchText) {
  return {
    message,
    position: idx,
    snippet: makeSnippet(code, idx),
    match: matchText,
  };
}

export function makeSnippet(code, idx, context = 60) {
  const start = Math.max(0, idx - context);
  const end = Math.min(code.length, idx + context);
  return code.slice(start, end).replace(/\n/g, ' ');
}

export function slicePreview(s, max = 100) {
  if (s.length <= max) return s;
  return s.slice(0, Math.floor(max / 2)) + '…' + s.slice(s.length - Math.floor(max / 2));
}

/**
 * Check if bundle appears to be minified
 */
export function isBundleMinified(code) {
  // Sample first 10KB
  const sample = code.slice(0, 10000);
  const lines = sample.split('\n');
  
  // Minified bundles have very long lines
  const avgLineLength = sample.length / lines.length;
  const hasLongLines = lines.some(l => l.length > 500);
  
  // Check for common minification patterns
  const hasMinifiedPatterns = /[a-z]\.[a-z]\([a-z]\)/.test(sample);
  
  return avgLineLength > 200 || (hasLongLines && hasMinifiedPatterns);
}

/**
 * Extract string literals from code
 */
export function extractStrings(code, minLength = 8) {
  const strings = [];
  const stringish = /(?:"([^"\\]{8,})"|'([^'\\]{8,})'|`([^`\\]{8,})`)/g;
  let m;
  while ((m = stringish.exec(code))) {
    const value = m[1] || m[2] || m[3] || '';
    if (value.trim().length >= minLength) {
      strings.push({ value: value.trim(), index: m.index });
    }
  }
  return strings;
}

/**
 * Check if code contains specific library/module
 */
export function hasModule(code, moduleName) {
  const patterns = [
    new RegExp(`require\\s*\\(['"]\s*${moduleName}\\s*['"]\\)`, 'i'),
    new RegExp(`from\\s+['"]${moduleName}['"]`, 'i'),
    new RegExp(`import.*${moduleName}`, 'i'),
  ];
  return patterns.some(p => p.test(code));
}

/**
 * Extract version from code (for libraries)
 */
export function extractVersion(code, libraryName) {
  const versionPattern = new RegExp(`${libraryName}.*version.*?["']([0-9.]+)["']`, 'gi');
  const match = versionPattern.exec(code);
  return match ? match[1] : null;
}

