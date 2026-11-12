import test from 'node:test';
import assert from 'node:assert/strict';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

test('init writes a valid manifest and empty lock', (t) => {
  const root = makeProject(t);
  const result = ok(root, 'init', 'demo-app');
  assert.match(result.stdout, /initialized demo-app/);
  assert.deepEqual(readJson(root, 'opurom.json'), {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  assert.deepEqual(readJson(root, 'opurom.lock'), { version: 1, packages: [] });
  assert.match(ok(root, 'verify').stdout, /1\/1 checks passed/);
});

test('init refuses to overwrite an initialized project', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  const result = run(root, 'init', 'other-app');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /already exists/);
  assert.equal(readJson(root, 'opurom.json').name, 'demo-app');
});

test('manifest validation rejects traversal and malformed fields', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');

  let manifest = readJson(root, 'opurom.json');
  manifest.moduleRoots = ['../outside'];
  writeJson(root, 'opurom.json', manifest);
  let result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /traversal/);

  manifest = readJson(root, 'opurom.json');
  manifest.moduleRoots = ['registry'];
  manifest.version = '0.1';
  writeJson(root, 'opurom.json', manifest);
  result = run(root, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid version/);

  manifest = readJson(root, 'opurom.json');
  manifest.version = '0.1.0';
  manifest.dependencies = { '../evil': '0.1.0' };
  writeJson(root, 'opurom.json', manifest);
  result = run(root, 'lock');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid dependency name/);

  manifest = readJson(root, 'opurom.json');
  delete manifest.dependencies;
  writeJson(root, 'opurom.json', manifest);
  result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /dependencies must be an object/);
});
