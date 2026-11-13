import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeProject, ok, readJson, run, seededProject, writeJson } from '../lib/helpers.mjs';

function lockText(root) {
  return readFileSync(path.join(root, 'opurom.lock'), 'utf8');
}

test('lock --check accepts a current lock without rewriting it', (t) => {
  const root = seededProject(t);
  const before = lockText(root);
  const result = ok(root, 'lock', '--check');
  assert.match(result.stdout, /opurom\.lock is up to date \(2 packages\)/);
  assert.equal(lockText(root), before);
});

test('lock --check rejects a reformatted lock that verify accepts', (t) => {
  const root = seededProject(t);
  const reformatted = `${JSON.stringify(readJson(root, 'opurom.lock'), null, 4)}\n`;
  writeFileSync(path.join(root, 'opurom.lock'), reformatted);
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
  const result = run(root, 'lock', '--check');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /stale/);
  assert.equal(lockText(root), reformatted);
});

test('lock --check detects changed registry bytes without rewriting the lock', (t) => {
  const root = seededProject(t);
  const file = path.join(root, 'registry', 'opurom-ui', '0.1.0', 'button.opu');
  writeFileSync(file, `${readFileSync(file, 'utf8')}\nstate extra = 0\n`);
  const before = lockText(root);
  const result = run(root, 'lock', '--check');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /stale/);
  assert.equal(lockText(root), before);
});

test('lock --check detects manifest drift without rewriting the lock', (t) => {
  const root = seededProject(t);
  const manifest = readJson(root, 'opurom.json');
  delete manifest.dependencies['opurom-ui'];
  writeJson(root, 'opurom.json', manifest);
  const before = lockText(root);
  const result = run(root, 'lock', '--check');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /stale/);
  assert.equal(lockText(root), before);
});

test('lock --check accepts an empty deterministic lock', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  const result = ok(root, 'lock', '--check');
  assert.match(result.stdout, /up to date \(0 packages\)/);
});

test('lock --check reports a missing lockfile', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  rmSync(path.join(root, 'opurom.lock'));
  const result = run(root, 'lock', '--check');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing opurom\.lock/);
});

test('lock --check rejects extra arguments', (t) => {
  const root = seededProject(t);
  const result = run(root, 'lock', '--check', 'extra');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /lock takes no arguments or --check/);
});
