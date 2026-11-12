import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, seededProject, writeJson } from '../lib/helpers.mjs';

test('verify passes on clean packages', (t) => {
  const root = seededProject(t);
  const result = ok(root, 'verify');
  assert.match(result.stdout, /PASS  <manifest>/);
  assert.match(result.stdout, /PASS  opurom-data@0\.1\.0/);
  assert.match(result.stdout, /PASS  opurom-ui@0\.1\.0/);
  assert.match(result.stdout, /3\/3 checks passed/);
});

test('verify fails on a tampered file', (t) => {
  const root = seededProject(t);
  const file = path.join(root, 'registry', 'opurom-ui', '0.1.0', 'button.opu');
  writeFileSync(file, `${readFileSync(file, 'utf8')}\nstate tampered = 0\n`);
  const result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /checksum mismatch: registry\/opurom-ui\/0\.1\.0\/button\.opu/);
});

test('verify fails on a missing file', (t) => {
  const root = seededProject(t);
  rmSync(path.join(root, 'registry', 'opurom-ui', '0.1.0', 'card.opu'));
  const result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing locked file|file list drift/);
  assert.match(result.output, /card\.opu/);
});

test('verify fails on traversal paths', (t) => {
  const root = seededProject(t);
  const lock = readJson(root, 'opurom.lock');
  lock.packages[0].files[0].path = '../../etc/passwd';
  writeJson(root, 'opurom.lock', lock);
  let result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /traversal/);

  const packageRoot = seededProject(t);
  const packageLock = readJson(packageRoot, 'opurom.lock');
  packageLock.packages[0].path = '../outside';
  for (const file of packageLock.packages[0].files) {
    file.path = path.posix.join('../outside', path.basename(file.path));
  }
  writeJson(packageRoot, 'opurom.lock', packageLock);
  result = run(packageRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /traversal/);
});

test('verify fails on invalid versions', (t) => {
  const root = seededProject(t);
  const lock = readJson(root, 'opurom.lock');
  lock.packages[0].version = '0.1';
  writeJson(root, 'opurom.lock', lock);
  let result = run(root, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid version/);

  const manifestRoot = seededProject(t);
  const manifest = readJson(manifestRoot, 'opurom.json');
  manifest.dependencies['opurom-ui'] = '0.1';
  writeJson(manifestRoot, 'opurom.json', manifest);
  result = run(manifestRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid version/);
});

test('unknown package is rejected and verify reports drift', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  const add = run(root, 'add', 'opurom-missing@0.1.0');
  assert.notEqual(add.status, 0);
  assert.match(add.output, /unknown local package/);

  const driftRoot = seededProject(t);
  const manifest = readJson(driftRoot, 'opurom.json');
  manifest.dependencies['opurom-unknown'] = '0.1.0';
  writeJson(driftRoot, 'opurom.json', manifest);
  const result = run(driftRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing locked package: opurom-unknown@0\.1\.0/);
});

test('verify fails on lock drift', (t) => {
  const manifestRoot = seededProject(t);
  const manifest = readJson(manifestRoot, 'opurom.json');
  manifest.dependencies['opurom-ui'] = '9.9.9';
  writeJson(manifestRoot, 'opurom.json', manifest);
  let result = run(manifestRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /version drift/);

  const digestRoot = seededProject(t);
  const lock = readJson(digestRoot, 'opurom.lock');
  lock.packages[0].sha256 = 'f'.repeat(64);
  writeJson(digestRoot, 'opurom.lock', lock);
  result = run(digestRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /package sha256 drift/);

  const extraRoot = seededProject(t);
  writeFileSync(
    path.join(extraRoot, 'registry', 'opurom-ui', '0.1.0', 'extra.opu'),
    'state extra = 0\n',
  );
  result = run(extraRoot, 'verify');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /file list drift/);
});
