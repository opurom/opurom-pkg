import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LOCKFILE, REPO, makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

test('add, list, remove round trip', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  ok(root, 'add', 'opurom-ui@0.1.0');
  ok(root, 'add', 'opurom-data@0.1.0');

  const list = ok(root, 'list');
  assert.match(list.stdout, /opurom-data\s+0\.1\.0/);
  assert.match(list.stdout, /opurom-ui\s+0\.1\.0/);
  assert.ok(list.stdout.indexOf('opurom-data') < list.stdout.indexOf('opurom-ui'));
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, {
    'opurom-data': '0.1.0',
    'opurom-ui': '0.1.0',
  });
  assert.deepEqual(
    readJson(root, 'opurom.lock').packages.map((pkg) => pkg.name),
    ['opurom-data', 'opurom-ui'],
  );

  ok(root, 'remove', 'opurom-ui');
  const after = ok(root, 'list');
  assert.match(after.stdout, /opurom-data/);
  assert.doesNotMatch(after.stdout, /opurom-ui/);
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, {
    'opurom-data': '0.1.0',
  });
  assert.deepEqual(
    readJson(root, 'opurom.lock').packages.map((pkg) => pkg.name),
    ['opurom-data'],
  );
  assert.match(ok(root, 'verify').stdout, /2\/2 checks passed/);

  const repeated = run(root, 'remove', 'opurom-ui');
  assert.notEqual(repeated.status, 0);
  assert.match(repeated.output, /unknown dependency/);
});

test('lock regeneration is byte stable and matches committed lock', (t) => {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', readJson(REPO, 'opurom.json'));
  ok(root, 'lock');
  const first = readFileSync(`${root}/opurom.lock`);
  ok(root, 'lock');
  const second = readFileSync(`${root}/opurom.lock`);
  assert.equal(first.toString('utf8'), second.toString('utf8'));
  const lock = JSON.parse(first.toString('utf8'));
  assert.match(lock.manifestSha256, /^[0-9a-f]{64}$/);
  const committed = JSON.parse(readFileSync(LOCKFILE, 'utf8'));
  assert.match(committed.manifestSha256, /^[0-9a-f]{64}$/);
  delete lock.manifestSha256;
  delete committed.manifestSha256;
  assert.equal(`${JSON.stringify(lock, null, 2)}\n`, `${JSON.stringify(committed, null, 2)}\n`);
  assert.equal(lock.version, 1);
  assert.deepEqual(lock.packages.map((pkg) => pkg.name), ['opurom-data', 'opurom-ui']);
  for (const pkg of lock.packages) {
    const filePaths = pkg.files.map((file) => file.path);
    assert.deepEqual(filePaths, [...filePaths].sort());
    assert.match(pkg.sha256, /^[0-9a-f]{64}$/);
  }
});

test('invalid version and unknown package are rejected', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');

  let result = run(root, 'add', 'opurom-ui@0.1');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid version/);
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, {});

  result = run(root, 'add', 'opurom-missing@0.1.0');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /unknown local package/);
  assert.deepEqual(readJson(root, 'opurom.json').dependencies, {});

  result = run(root, 'add', 'opurom-ui');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /add needs/);

  result = run(root, 'add', '../evil@0.1.0');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid package name/);
});

test('show prints one locked package metadata from opurom.lock', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  ok(root, 'add', 'opurom-ui@0.1.0');

  const shown = ok(root, 'show', 'opurom-ui');
  assert.match(shown.stdout, /opurom-ui\s+0\.1\.0\s+3\s+registry\/opurom-ui\/0\.1\.0\s+[0-9a-f]{64}/);
  for (const file of ['button.opu', 'card.opu', 'opurom-pkg.json']) {
    assert.match(shown.stdout, new RegExp(`[0-9a-f]{64}  registry/opurom-ui/0\\.1\\.0/${file}`));
  }

  const missing = run(root, 'show', 'opurom-data');
  assert.notEqual(missing.status, 0);
  assert.match(missing.output, /unknown locked package: opurom-data/);

  const empty = run(root, 'show');
  assert.notEqual(empty.status, 0);
  assert.match(empty.output, /show needs exactly one argument/);
});
