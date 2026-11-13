import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  makeProject,
  ok,
  readJson,
  run,
  runWithEnv,
  seededProject,
  startRegistry,
  writeJson,
} from '../lib/helpers.mjs';
import { readSignature, writeSignature } from '../lib/signing.mjs';

function digest(root, relative) {
  return createHash('sha256').update(readFileSync(path.join(root, relative))).digest('hex');
}

function editVersion(root) {
  const manifest = readJson(root, 'opurom.json');
  manifest.version = '0.2.0';
  writeJson(root, 'opurom.json', manifest);
}

test('lock records the manifest digest and verify --signed checks it', (t) => {
  const root = seededProject(t);
  assert.equal(readJson(root, 'opurom.lock').manifestSha256, digest(root, 'opurom.json'));
  ok(root, 'sign');
  assert.match(ok(root, 'verify', '--signed').stdout, /3\/3 checks passed/);
});

test('install over a real registry records the manifest digest', async (t) => {
  const serverRoot = seededProject(t);
  const { url } = await startRegistry(t, serverRoot);
  const client = makeProject(t);
  ok(client, 'init', 'demo-app');
  const installed = runWithEnv(
    client,
    { OPUROM_REGISTRY_URL: url },
    'install',
    'opurom-ui@0.1.0',
  );
  assert.equal(installed.status, 0, installed.output);
  assert.equal(readJson(client, 'opurom.lock').manifestSha256, digest(client, 'opurom.json'));
  ok(client, 'sign');
  assert.match(ok(client, 'verify', '--signed').stdout, /2\/2 checks passed/);
});

test('add and remove refresh the recorded manifest digest', (t) => {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  assert.equal(readJson(root, 'opurom.lock').manifestSha256, digest(root, 'opurom.json'));
  ok(root, 'add', 'opurom-ui@0.1.0');
  const added = readJson(root, 'opurom.lock').manifestSha256;
  assert.equal(added, digest(root, 'opurom.json'));
  ok(root, 'remove', 'opurom-ui');
  const removed = readJson(root, 'opurom.lock').manifestSha256;
  assert.notEqual(removed, added);
  assert.equal(removed, digest(root, 'opurom.json'));
});

test('verify --signed rejects a manifest edited after install', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  editVersion(root);
  // A hash-only verify cannot see an edit that leaves dependencies unchanged.
  assert.match(ok(root, 'verify').stdout, /3\/3 checks passed/);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /manifest digest mismatch: opurom\.json/);
  assert.match(result.output, /2\/3 checks passed/);
});

test('lock refreshes the digest after a legitimate manifest edit', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  const before = readJson(root, 'opurom.lock').manifestSha256;
  editVersion(root);
  assert.notEqual(run(root, 'verify', '--signed').status, 0);
  ok(root, 'lock');
  const after = readJson(root, 'opurom.lock').manifestSha256;
  assert.notEqual(after, before);
  assert.equal(after, digest(root, 'opurom.json'));
  ok(root, 'sign');
  assert.match(ok(root, 'verify', '--signed').stdout, /3\/3 checks passed/);
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('lock --check reports a reformatted manifest until lock refreshes it', (t) => {
  const root = seededProject(t);
  writeFileSync(
    path.join(root, 'opurom.json'),
    `${JSON.stringify(readJson(root, 'opurom.json'), null, 4)}\n`,
  );
  const stale = run(root, 'lock', '--check');
  assert.notEqual(stale.status, 0);
  assert.match(stale.output, /stale/);
  ok(root, 'lock');
  assert.equal(readJson(root, 'opurom.lock').manifestSha256, digest(root, 'opurom.json'));
  assert.match(ok(root, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('verify --signed refuses a rewritten digest with a stale signature', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  editVersion(root);
  const lock = readJson(root, 'opurom.lock');
  lock.manifestSha256 = digest(root, 'opurom.json');
  writeJson(root, 'opurom.lock', lock);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature: opurom\.lock\.sig/);
  assert.doesNotMatch(result.output, /3\/3 checks passed/);
});

test('verify --signed refuses a tampered lockfile signature', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  const signature = Buffer.from(readSignature(root, 'opurom.lock'));
  signature[0] ^= 0xff;
  writeSignature(root, 'opurom.lock', signature);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature: opurom\.lock\.sig/);
});

test('verify --signed refuses a signed lock without a manifest digest', (t) => {
  const root = seededProject(t);
  const lock = readJson(root, 'opurom.lock');
  delete lock.manifestSha256;
  writeJson(root, 'opurom.lock', lock);
  ok(root, 'sign');
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing manifestSha256 in opurom\.lock/);
});

test('a malformed manifest digest is rejected when reading the lock', (t) => {
  const root = seededProject(t);
  const lock = readJson(root, 'opurom.lock');
  lock.manifestSha256 = 'not-a-digest';
  writeJson(root, 'opurom.lock', lock);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid manifestSha256 in opurom\.lock/);
});
