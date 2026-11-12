import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { CLI, REPO, makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

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

test('mutations from an uninitialized directory never touch the tool repo', () => {
  const bare = mkdtempSync(path.join(tmpdir(), 'opurom-pkg-bare-'));
  const before = readFileSync(path.join(REPO, 'opurom.json'), 'utf8');
  try {
    const install = run(bare, 'install', 'opurom-ui@0.1.0');
    assert.notEqual(install.status, 0, 'install outside a project must fail');
    assert.match(install.output, /no opurom\.json|init/i);
    const add = run(bare, 'add', 'opurom-ui@0.1.0');
    assert.notEqual(add.status, 0, 'add outside a project must fail');
    assert.match(add.output, /no opurom\.json|init/i);
    assert.equal(readFileSync(path.join(REPO, 'opurom.json'), 'utf8'), before,
      'the packaged manifest must not be rewritten');
    assert.equal(existsSync(path.join(bare, 'opurom.json')), false,
      'a failed mutation must not create files');
  } finally {
    rmSync(bare, { recursive: true, force: true });
  }
});

test('init in a truly empty directory writes there, not into the tool repo', () => {
  const bare = mkdtempSync(path.join(tmpdir(), 'opurom-pkg-init-'));
  const before = readFileSync(path.join(REPO, 'opurom.json'), 'utf8');
  try {
    const result = ok(bare, 'init', 'fresh-app');
    assert.match(result.stdout, /initialized fresh-app/);
    assert.equal(readJson(bare, 'opurom.json').name, 'fresh-app');
    assert.equal(readFileSync(path.join(REPO, 'opurom.json'), 'utf8'), before);
  } finally {
    rmSync(bare, { recursive: true, force: true });
  }
});
