import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

function writePackage(root, name, version, dependencies) {
  const relative = path.posix.join('registry', name, version);
  mkdirSync(path.join(root, relative), { recursive: true });
  const manifest = { name, version, files: ['opurom-pkg.json'] };
  if (dependencies !== undefined) manifest.dependencies = dependencies;
  writeJson(root, `${relative}/opurom-pkg.json`, manifest);
}

function project(t, dependencies) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies,
  });
  return root;
}

function locked(root) {
  return readJson(root, 'opurom.lock').packages.map((pkg) => `${pkg.name}@${pkg.version}`);
}

test('lock resolves transitive requirements into the tree', (t) => {
  const root = project(t, { 'tree-app': '>=1.0.0' });
  writePackage(root, 'tree-app', '1.0.0', { 'tree-lib': '>=1.0.0 <2.0.0' });
  writePackage(root, 'tree-app', '1.2.0', { 'tree-lib': '>=1.0.0 <2.0.0' });
  writePackage(root, 'tree-lib', '1.0.0');
  writePackage(root, 'tree-lib', '1.5.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['tree-app@1.2.0', 'tree-lib@1.5.0']);
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('one pinned version satisfies every requirement on a shared dependency', (t) => {
  const root = project(t, { 'tree-a': '1.0.0', 'tree-c': '1.0.0' });
  writePackage(root, 'tree-a', '1.0.0', { 'tree-b': '>=1.0.0' });
  writePackage(root, 'tree-c', '1.0.0', { 'tree-b': '<1.1.0' });
  writePackage(root, 'tree-b', '1.0.0');
  writePackage(root, 'tree-b', '1.1.0');
  writePackage(root, 'tree-b', '1.2.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['tree-a@1.0.0', 'tree-b@1.0.0', 'tree-c@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /4\/4 checks passed/);
});

test('conflicting requirements fail with the requirer of each one', (t) => {
  const root = project(t, { 'tree-a': '1.0.0', 'tree-b': '1.0.0' });
  writePackage(root, 'tree-a', '1.0.0', { 'tree-b': '>=2.0.0' });
  writePackage(root, 'tree-b', '1.0.0');
  writePackage(root, 'tree-b', '2.0.0');

  const result = run(root, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /dependency conflict: tree-b/);
  assert.match(result.output, /opurom\.json requires 1\.0\.0/);
  assert.match(result.output, /tree-a@1\.0\.0 requires >=2\.0\.0/);
  assert.match(result.output, /no version of tree-b satisfies all constraints/);
});

test('a later requirement backtracks an earlier choice', (t) => {
  const root = project(t, { 'tree-a': '>=1.0.0', 'tree-b': '1.0.0' });
  writePackage(root, 'tree-a', '1.0.0', { 'tree-b': '>=1.0.0' });
  writePackage(root, 'tree-a', '2.0.0', { 'tree-b': '>=2.0.0' });
  writePackage(root, 'tree-b', '1.0.0');
  writePackage(root, 'tree-b', '2.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['tree-a@1.0.0', 'tree-b@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
});

test('a dependency cycle resolves without recursing forever', (t) => {
  const root = project(t, { 'tree-cyc': '1.0.0' });
  writePackage(root, 'tree-cyc', '1.0.0', { 'tree-cyc2': '1.0.0' });
  writePackage(root, 'tree-cyc2', '1.0.0', { 'tree-cyc': '1.0.0' });

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['tree-cyc@1.0.0', 'tree-cyc2@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
});

test('a malformed dependency contract in a registry manifest is refused', (t) => {
  const root = project(t, { 'tree-app': '1.0.0' });
  writePackage(root, 'tree-app', '1.0.0', { 'tree-lib': 'oops' });

  const result = run(root, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid version for dependency tree-lib of tree-app@1\.0\.0/);
});

test('verify reports lock gaps for transitive packages', (t) => {
  const missing = project(t, { 'tree-app': '1.0.0' });
  writePackage(missing, 'tree-app', '1.0.0', { 'tree-lib': '1.5.0' });
  writePackage(missing, 'tree-lib', '1.5.0');
  ok(missing, 'lock');
  const lock = readJson(missing, 'opurom.lock');
  lock.packages = lock.packages.filter((pkg) => pkg.name !== 'tree-lib');
  writeJson(missing, 'opurom.lock', lock);
  const missingResult = run(missing, 'verify');
  assert.notEqual(missingResult.status, 0);
  assert.match(missingResult.output, /missing locked package: tree-lib@1\.5\.0 \(transitive\)/);

  const drifted = project(t, { 'tree-app': '1.0.0' });
  writePackage(drifted, 'tree-app', '1.0.0', { 'tree-lib': '1.5.0' });
  writePackage(drifted, 'tree-lib', '1.5.0');
  ok(drifted, 'lock');
  // A newer transitive release leaves the stale pin behind after the parent manifest moves.
  writePackage(drifted, 'tree-app', '1.0.0', { 'tree-lib': '2.0.0' });
  writePackage(drifted, 'tree-lib', '2.0.0');
  const driftResult = run(drifted, 'verify');
  assert.notEqual(driftResult.status, 0);
  assert.match(driftResult.output, /version drift: tree-lib expected 2\.0\.0, lock has 1\.5\.0/);
});
