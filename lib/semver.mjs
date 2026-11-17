// SemVer 2.0 parsing, precedence and comparator-set ranges. Node builtins only.
const VERSION_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const COMPARATOR_RE = /^(>=|<=|>|<|=)(.+)$/;
const NUMERIC_RE = /^\d+$/;

// SemVer 2.0 forbids leading zeros in numeric prerelease identifiers. Build
// metadata identifiers have no such restriction, and never affect precedence.
function validPrerelease(identifiers) {
  return identifiers.every(
    (identifier) =>
      !NUMERIC_RE.test(identifier) || identifier === '0' || !identifier.startsWith('0'),
  );
}

export function parseVersion(value) {
  if (typeof value !== 'string') return null;
  const match = VERSION_RE.exec(value);
  if (!match) return null;
  const prerelease = match[4] === undefined ? [] : match[4].split('.');
  if (!validPrerelease(prerelease)) return null;
  return {
    raw: value,
    core: [match[1], match[2], match[3]],
    prerelease,
  };
}

function sameCore(left, right) {
  return left.core.every((part, index) => part === right.core[index]);
}

// Pure SemVer 2.0 precedence. Build metadata is ignored, so versions differing
// only by build metadata compare equal here.
export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) throw new TypeError(`invalid SemVer version: ${left} / ${right}`);
  for (let index = 0; index < 3; index += 1) {
    const x = BigInt(a.core[index]);
    const y = BigInt(b.core[index]);
    if (x < y) return -1;
    if (x > y) return 1;
  }
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    if (a.prerelease.length === b.prerelease.length) return 0;
    return a.prerelease.length === 0 ? 1 : -1;
  }
  for (let index = 0; index < Math.min(a.prerelease.length, b.prerelease.length); index += 1) {
    const x = a.prerelease[index];
    const y = b.prerelease[index];
    const xNumeric = NUMERIC_RE.test(x);
    const yNumeric = NUMERIC_RE.test(y);
    if (xNumeric && yNumeric) {
      const xi = BigInt(x);
      const yi = BigInt(y);
      if (xi < yi) return -1;
      if (xi > yi) return 1;
    } else if (xNumeric !== yNumeric) {
      return xNumeric ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return Math.sign(a.prerelease.length - b.prerelease.length);
}

// Total order for resolution: precedence first, then raw text, so versions
// equal by precedence (build metadata only) are still selected deterministically.
export function compareVersionOrder(left, right) {
  const order = compareVersions(left, right);
  if (order !== 0) return order;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

// Pub-style caret compatibility: the upper bound is the next breaking
// version, which bumps minor while major is zero and major otherwise. Build
// the bound with BigInt so arbitrary-length core identifiers stay exact.
function caretUpper(version) {
  const major = BigInt(version.core[0]);
  if (major === 0n) return `${major}.${BigInt(version.core[1]) + 1n}.0`;
  return `${major + 1n}.0.0`;
}

// A contract is one exact version, a caret range like "^1.2.3", or
// whitespace-separated comparators such as ">=1.0.0 <2.0.0". A prerelease
// only satisfies a range that contains a prerelease comparator for the same
// major.minor.patch tuple.
export function parseRange(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const exact = parseVersion(value);
  if (exact) return { exact: true, version: exact, raw: value };
  if (value.startsWith('^')) {
    const text = value.slice(1).trim();
    const version = parseVersion(text);
    // Caret accepts one version only; trailing text or whitespace is invalid.
    if (!version || version.raw !== text || /\s/.test(text)) return null;
    const upper = parseVersion(caretUpper(version));
    return {
      exact: false,
      comparators: [
        { operator: '>=', version },
        { operator: '<', version: upper },
      ],
      raw: value,
    };
  }
  const tokens = value.trim().split(/\s+/);
  const comparators = [];
  for (const token of tokens) {
    const match = COMPARATOR_RE.exec(token);
    const version = match && parseVersion(match[2]);
    if (!version) return null;
    comparators.push({ operator: match[1], version });
  }
  if (comparators.length === 0) return null;
  return { exact: false, comparators, raw: value };
}

export function satisfies(value, range) {
  const version = parseVersion(value);
  if (!version || !range) return false;
  if (range.exact) return value === range.raw;
  if (
    version.prerelease.length > 0 &&
    !range.comparators.some(
      (comparator) =>
        comparator.version.prerelease.length > 0 && sameCore(comparator.version, version),
    )
  ) {
    return false;
  }
  return range.comparators.every((comparator) => {
    const order = compareVersions(value, comparator.version.raw);
    switch (comparator.operator) {
      case '>=':
        return order >= 0;
      case '>':
        return order > 0;
      case '<=':
        return order <= 0;
      case '<':
        return order < 0;
      default:
        return order === 0;
    }
  });
}

export function highestSatisfying(range, versions) {
  let best = null;
  for (const candidate of versions) {
    if (!parseVersion(candidate) || !satisfies(candidate, range)) continue;
    if (best === null || compareVersionOrder(candidate, best) > 0) best = candidate;
  }
  return best;
}
