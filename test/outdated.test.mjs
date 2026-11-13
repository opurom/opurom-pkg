import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, writeJson } from '../lib/helpers.mjs';

function addRegistryVersion(root, name, version) {
  mkdirSync(path.join(root, 'registry', name, version), { recursive: true });
}

function writeManifest(root, dependencies) {
  writeJson(root, 'opurom.json', {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies,
  });
}

test('outdated reports a newer registry version without writing the lock', (t) => {
  const root = makeProject(t);
  writeManifest(root, { 'opurom-data': '0.1.0', 'opurom-ui': '0.1.0' });
  ok(root, 'lock');
  addRegistryVersion(root, 'opurom-ui', '0.2.0');

  const before = readFileSync(path.join(root, 'opurom.lock'), 'utf8');
  const result = ok(root, 'outdated');
  const after = readFileSync(path.join(root, 'opurom.lock'), 'utf8');
  assert.equal(before, after, 'outdated must not rewrite opurom.lock');
  assert.match(result.stdout, /NAME\s+LOCKED\s+WANTED\s+LATEST/);
  assert.match(result.stdout, /opurom-ui\s+0\.1\.0\s+0\.1\.0\s+0\.2\.0/);
  assert.doesNotMatch(result.stdout, /opurom-data/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('outdated shows the wanted upgrade inside the declared range', (t) => {
  const root = makeProject(t);
  writeManifest(root, { 'opurom-ui': '>=0.1.0 <0.3.0' });
  ok(root, 'lock');
  assert.equal(readJson(root, 'opurom.lock').packages[0].version, '0.1.0');
  addRegistryVersion(root, 'opurom-ui', '0.2.0');
  addRegistryVersion(root, 'opurom-ui', '0.3.0-beta.1');

  const result = ok(root, 'outdated');
  assert.match(result.stdout, /opurom-ui\s+0\.1\.0\s+0\.2\.0\s+0\.2\.0/);
  assert.doesNotMatch(result.stdout, /0\.3\.0-beta/);
});

test('outdated output is byte identical across runs and registry orders', (t) => {
  const build = (owner, entries) => {
    const root = makeProject(owner);
    writeManifest(root, { 'opurom-data': '>=0.1.0', 'opurom-ui': '>=0.1.0' });
    ok(root, 'lock');
    for (const [name, version] of entries) addRegistryVersion(root, name, version);
    return root;
  };
  const first = build(t, [
    ['opurom-data', '0.2.0'],
    ['opurom-ui', '0.3.0'],
    ['opurom-ui', '0.2.0'],
  ]);
  const second = build(t, [
    ['opurom-ui', '0.2.0'],
    ['opurom-ui', '0.3.0'],
    ['opurom-data', '0.2.0'],
  ]);

  const firstRun = ok(first, 'outdated').stdout;
  assert.equal(firstRun, ok(first, 'outdated').stdout, 'repeated runs must match');
  assert.equal(firstRun, ok(second, 'outdated').stdout, 'registry order must not matter');
  assert.match(
    firstRun,
    /opurom-data\s+0\.1\.0\s+0\.2\.0\s+0\.2\.0\nopurom-ui\s+0\.1\.0\s+0\.3\.0\s+0\.3\.0/,
  );
});

test('outdated reports an up-to-date project and a missing registry package', (t) => {
  const root = makeProject(t);
  writeManifest(root, { 'opurom-data': '0.1.0', 'opurom-ui': '0.1.0' });
  ok(root, 'lock');

  const current = ok(root, 'outdated');
  assert.equal(current.stdout, 'all locked packages are up to date\n');

  rmSync(path.join(root, 'registry', 'opurom-ui'), { recursive: true, force: true });
  const missing = run(root, 'outdated');
  assert.notEqual(missing.status, 0);
  assert.match(missing.output, /missing registry for opurom-ui/);
});
