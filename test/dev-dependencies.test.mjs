import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

function writePackage(root, name, version, extra = {}) {
  const directory = path.join(root, 'registry', name, version);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, 'extra.opu'), `state ${name} = ${version}\n`);
  writeJson(root, path.posix.join('registry', name, version, 'opurom-pkg.json'), {
    name,
    version,
    files: ['extra.opu', 'opurom-pkg.json'],
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

test('root devDependencies resolve into the lock and survive add/remove', (t) => {
  const root = project(t, { devDependencies: { 'dev-tool': '1.0.0' } });
  writePackage(root, 'dev-tool', '1.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['dev-tool@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(1 packages\)/);

  ok(root, 'add', 'opurom-ui@0.1.0');
  assert.deepEqual(locked(root), ['dev-tool@1.0.0', 'opurom-ui@0.1.0']);
  assert.deepEqual(readJson(root, 'opurom.json').devDependencies, { 'dev-tool': '1.0.0' });
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);

  ok(root, 'remove', 'opurom-ui');
  assert.deepEqual(locked(root), ['dev-tool@1.0.0']);
  assert.deepEqual(readJson(root, 'opurom.json').devDependencies, { 'dev-tool': '1.0.0' });
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(1 packages\)/);
});

test('a dependency manifest devDependencies are not resolved transitively', (t) => {
  const root = project(t, { dependencies: { 'prod-app': '1.0.0' } });
  writePackage(root, 'prod-app', '1.0.0', { devDependencies: { 'hidden-tool': '1.0.0' } });
  writePackage(root, 'hidden-tool', '1.0.0');

  ok(root, 'lock');
  assert.deepEqual(locked(root), ['prod-app@1.0.0']);
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(1 packages\)/);
});

test('devDependencies format and duplicate declarations are rejected', (t) => {
  const bad = project(t, { devDependencies: 'not-an-object' });
  let result = run(bad, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /devDependencies must be an object/);

  const duplicate = project(t, {
    dependencies: { 'dev-tool': '1.0.0' },
    devDependencies: { 'dev-tool': '1.0.0' },
  });
  result = run(duplicate, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /dependency dev-tool declared twice/);
});
