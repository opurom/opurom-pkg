import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

function writePackage(root, name, version, extra = {}) {
  const directory = path.join(root, 'registry', name, version);
  mkdirSync(directory, { recursive: true });
  writeJson(root, path.posix.join('registry', name, version, 'opurom-pkg.json'), {
    name,
    version,
    files: ['opurom-pkg.json'],
    ...extra,
  });
}

function project(t, fields) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
    ...fields,
  });
  return root;
}

function locked(root) {
  return readJson(root, 'opurom.lock').packages.map((pkg) => `${pkg.name}@${pkg.version}`);
}

test('a root override replaces a transitive requirement', (t) => {
  const root = project(t, {
    dependencies: { app: '1.0.0' },
    dependencyOverrides: { lib: '1.0.0' },
  });
  writePackage(root, 'app', '1.0.0', { dependencies: { lib: '>=2.0.0' } });
  writePackage(root, 'lib', '1.0.0');
  writePackage(root, 'lib', '2.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['app@1.0.0', 'lib@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(2 packages\)/);
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, { app: '1.0.0' });
  assert.deepEqual(readJson(root, 'opurom.json').dependencyOverrides, { lib: '1.0.0' });
});

test('an override also replaces the root declared constraint', (t) => {
  const root = project(t, {
    dependencies: { lib: '>=2.0.0' },
    dependencyOverrides: { lib: '1.0.0' },
  });
  writePackage(root, 'lib', '1.0.0');
  writePackage(root, 'lib', '2.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['lib@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(1 packages\)/);
});

test('overrides do not change resolution of other packages', (t) => {
  const root = project(t, {
    dependencies: { app: '1.0.0', other: '>=1.0.0' },
    dependencyOverrides: { lib: '1.0.0' },
  });
  writePackage(root, 'app', '1.0.0', { dependencies: { lib: '>=2.0.0' } });
  writePackage(root, 'lib', '1.0.0');
  writePackage(root, 'lib', '2.0.0');
  writePackage(root, 'other', '1.0.0');
  writePackage(root, 'other', '1.1.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['app@1.0.0', 'lib@1.0.0', 'other@1.1.0']);
  assert.match(ok(root, 'verify').stdout, /4\/4 checks passed/);
});

test('only the root manifest overrides apply', (t) => {
  const root = project(t, { dependencies: { app: '1.0.0' } });
  writePackage(root, 'app', '1.0.0', { dependencyOverrides: { lib: '1.0.0' } });
  writePackage(root, 'lib', '1.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['app@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
});

test('an invalid override is rejected and unchanged projects keep lock bytes', (t) => {
  const bad = project(t, { dependencyOverrides: 'not-an-object' });
  let result = run(bad, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /dependencyOverrides must be an object/);

  const stable = project(t, { dependencies: { lib: '1.0.0' } });
  writePackage(stable, 'lib', '1.0.0');
  ok(stable, 'lock');
  const before = readJson(stable, 'opurom.lock');
  ok(stable, 'lock');
  assert.deepEqual(readJson(stable, 'opurom.lock'), before);
  assert.match(ok(stable, 'lock', '--check').stdout, /up to date \(1 packages\)/);
});
