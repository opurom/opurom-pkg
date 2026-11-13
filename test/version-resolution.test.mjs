import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';
import {
  compareVersions,
  highestSatisfying,
  parseRange,
  parseVersion,
  satisfies,
} from '../lib/semver.mjs';

const NAME = 'opurom-semver';
const RANGE = '>=1.0.0 <2.0.0';

function addVersion(root, version) {
  const directory = path.join(root, 'registry', NAME, version);
  mkdirSync(directory, { recursive: true });
  const label = version.replace(/[^0-9A-Za-z]/g, '_');
  writeFileSync(path.join(directory, 'extra.opu'), `state ${label} = 1\n`);
  writeJson(root, `registry/${NAME}/${version}/opurom-pkg.json`, {
    name: NAME,
    version,
    files: ['extra.opu', 'opurom-pkg.json'],
  });
}

function rangedProject(t, versions, spec = RANGE) {
  const root = makeProject(t);
  for (const version of versions) addVersion(root, version);
  writeJson(root, 'opurom.json', {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: { [NAME]: spec },
  });
  return root;
}

function lockedVersion(root) {
  return readJson(root, 'opurom.lock').packages[0].version;
}

test('parseVersion rejects leading zeros in core and prerelease identifiers', () => {
  for (const value of [
    '01.2.3',
    '1.02.3',
    '1.2.03',
    '1.2.3-01',
    '1.2.3-beta.01',
    'v1.2.3',
    '1.2',
    '1.2.3-',
    '1.2.3+',
  ]) {
    assert.equal(parseVersion(value), null, value);
  }
  assert.deepEqual(parseVersion('1.2.3-rc.1+build.02').prerelease, ['rc', '1']);
  // Build metadata may contain leading zeros and never affects precedence.
  assert.equal(parseVersion('1.2.3+001').raw, '1.2.3+001');
});

test('compareVersions implements SemVer 2.0 precedence', () => {
  const ordered = [
    '1.0.0-alpha',
    '1.0.0-alpha.1',
    '1.0.0-alpha.beta',
    '1.0.0-beta',
    '1.0.0-beta.2',
    '1.0.0-beta.11',
    '1.0.0-rc.1',
    '1.0.0',
    '1.0.1',
    '1.1.0',
    '2.0.0',
  ];
  for (let index = 1; index < ordered.length; index += 1) {
    assert.ok(
      compareVersions(ordered[index - 1], ordered[index]) < 0,
      `${ordered[index - 1]} < ${ordered[index]}`,
    );
  }
  assert.ok(compareVersions('1.10.0', '1.9.0') > 0);
  assert.ok(compareVersions('1.0.0-1', '1.0.0-alpha') < 0);
  assert.equal(compareVersions('1.0.0+build.1', '1.0.0+build.2'), 0);
});

test('stable ranges exclude prereleases but allow same-tuple prerelease comparators', () => {
  const stable = parseRange(RANGE);
  assert.equal(satisfies('1.5.0', stable), true);
  assert.equal(satisfies('1.5.0-rc.1', stable), false);
  assert.equal(satisfies('2.0.0-beta.1', stable), false);
  assert.equal(satisfies('2.0.0', stable), false);

  const prerelease = parseRange('>=1.0.0-beta.1 <2.0.0');
  assert.equal(satisfies('1.0.0-beta.2', prerelease), true);
  assert.equal(satisfies('1.5.0-rc.1', prerelease), false);
  assert.equal(satisfies('1.0.0', prerelease), true);

  assert.equal(satisfies('1.2.3', parseRange('1.2.3')), true);
  assert.equal(satisfies('1.2.4', parseRange('1.2.3')), false);
  assert.equal(parseRange('01.2.3'), null);
  assert.equal(parseRange('>=1.0.0 <=oops'), null);
});

test('highestSatisfying breaks build metadata ties deterministically', () => {
  const range = parseRange(RANGE);
  assert.equal(
    highestSatisfying(range, ['1.2.3+build.2', '1.2.3+build.1']),
    '1.2.3+build.2',
  );
  assert.equal(
    highestSatisfying(range, ['1.2.3+build.1', '1.2.3+build.2']),
    '1.2.3+build.2',
  );
  assert.equal(highestSatisfying(range, ['1.0.0-rc.1', '2.0.0', '01.2.3']), null);
});

test('an exact spec wins over higher available versions', (t) => {
  const root = makeProject(t);
  for (const version of ['1.0.0', '1.10.0', '2.0.0']) addVersion(root, version);
  ok(root, 'init', 'demo-app');
  const result = ok(root, 'add', `${NAME}@1.0.0`);
  assert.match(result.stdout, /added opurom-semver@1\.0\.0/);
  assert.equal(lockedVersion(root), '1.0.0');
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, { [NAME]: '1.0.0' });
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
});

test('a stable range pins the numerically highest stable version', (t) => {
  const root = rangedProject(t, ['1.9.0', '1.10.0', '1.2.0', '2.0.0']);
  ok(root, 'lock');
  assert.equal(lockedVersion(root), '1.10.0');
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, { [NAME]: RANGE });
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(1 packages\)/);
  const before = readFileSync(path.join(root, 'opurom.lock'), 'utf8');
  ok(root, 'lock');
  assert.equal(readFileSync(path.join(root, 'opurom.lock'), 'utf8'), before);
});

test('a prerelease never satisfies a stable range', (t) => {
  const root = rangedProject(t, [
    '1.0.0',
    '1.10.0',
    '1.10.0-rc.1',
    '1.5.0-beta.1',
    '2.0.0-beta.1',
    '2.0.0',
  ]);
  ok(root, 'lock');
  assert.equal(lockedVersion(root), '1.10.0');
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
});

test('an explicit prerelease pin is allowed', (t) => {
  const root = rangedProject(t, ['1.0.0', '1.10.0', '1.10.0-rc.1'], '1.10.0-rc.1');
  ok(root, 'lock');
  assert.equal(lockedVersion(root), '1.10.0-rc.1');
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
});

test('selection is independent of registry directory order', (t) => {
  const first = rangedProject(t, ['1.9.0', '1.10.0', '1.2.0']);
  const second = rangedProject(t, ['1.2.0', '1.10.0', '1.9.0']);
  ok(first, 'lock');
  ok(second, 'lock');
  assert.equal(lockedVersion(first), '1.10.0');
  assert.equal(lockedVersion(second), '1.10.0');
  assert.equal(
    readFileSync(path.join(first, 'opurom.lock'), 'utf8'),
    readFileSync(path.join(second, 'opurom.lock'), 'utf8'),
  );
});

test('build metadata ties resolve deterministically through the CLI', (t) => {
  const root = rangedProject(t, ['1.2.3+build.1', '1.2.3+build.2']);
  ok(root, 'lock');
  assert.equal(lockedVersion(root), '1.2.3+build.2');
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date/);
});

test('leading-zero versions are refused in specs, registry and lock', (t) => {
  const specRoot = rangedProject(t, ['1.0.0']);
  for (const spec of [`${NAME}@01.2.3`, `${NAME}@1.2.3-beta.01`]) {
    const result = run(specRoot, 'add', spec);
    assert.notEqual(result.status, 0, spec);
    assert.match(result.output, /invalid version/);
  }
  assert.deepEqual(readJson(specRoot, 'opurom.json').dependencies, { [NAME]: RANGE });

  const registryRoot = rangedProject(t, ['1.0.0']);
  mkdirSync(path.join(registryRoot, 'registry', NAME, '01.2.3'), { recursive: true });
  const registryResult = run(registryRoot, 'lock');
  assert.notEqual(registryResult.status, 0);
  assert.match(registryResult.output, /invalid version/);

  const lockRoot = rangedProject(t, ['1.0.0']);
  ok(lockRoot, 'lock');
  const lock = readJson(lockRoot, 'opurom.lock');
  lock.packages[0].version = '01.0.0';
  writeJson(lockRoot, 'opurom.lock', lock);
  const lockResult = run(lockRoot, 'verify');
  assert.notEqual(lockResult.status, 0);
  assert.match(lockResult.output, /invalid version/);
});

test('a signed ranged lock passes verify --signed', (t) => {
  const root = rangedProject(t, ['1.0.0', '1.10.0']);
  ok(root, 'lock');
  ok(root, 'sign');
  assert.match(ok(root, 'verify', '--signed').stdout, /2\/2 checks passed/);
});

test('a tampered lockfile entry is refused', (t) => {
  const versions = ['1.0.0', '1.10.0'];
  const pinned = rangedProject(t, versions, '1.0.0');
  ok(pinned, 'lock');
  const entry = readJson(pinned, 'opurom.lock').packages[0];

  const root = rangedProject(t, versions);
  ok(root, 'lock');
  assert.equal(lockedVersion(root), '1.10.0');
  ok(root, 'sign');
  const lock = readJson(root, 'opurom.lock');
  lock.packages[0] = entry;
  writeJson(root, 'opurom.lock', lock);

  const unsigned = run(root, 'verify');
  assert.notEqual(unsigned.status, 0);
  assert.match(unsigned.output, /version drift/);
  const signed = run(root, 'verify', '--signed');
  assert.notEqual(signed.status, 0);
  assert.match(signed.output, /invalid signature: opurom\.lock\.sig/);
});

test('a tampered lockfile signature is refused', (t) => {
  const root = rangedProject(t, ['1.0.0', '1.10.0']);
  ok(root, 'lock');
  ok(root, 'sign');
  assert.match(ok(root, 'verify', '--signed').stdout, /2\/2 checks passed/);
  const signaturePath = path.join(root, 'opurom.lock.sig');
  const tampered = Buffer.from(readFileSync(signaturePath));
  tampered[0] ^= 0xff;
  writeFileSync(signaturePath, tampered);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature: opurom\.lock\.sig/);
});
