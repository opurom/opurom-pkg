import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ok, run, seededProject } from '../lib/helpers.mjs';

const SIGNED_FILE = path.join('registry', 'opurom-ui', '0.1.0', 'button.opu');

test('sign writes detached signatures and verify --signed passes', (t) => {
  const root = seededProject(t);
  const signed = ok(root, 'sign');
  assert.match(signed.stdout, /signed 7 files/);
  assert.ok(existsSync(path.join(root, 'keys', 'opurom.key')));
  assert.ok(existsSync(path.join(root, 'keys', 'opurom.pub')));
  assert.ok(existsSync(path.join(root, `${SIGNED_FILE}.sig`)));
  assert.ok(existsSync(path.join(root, 'opurom.lock.sig')));

  const verified = ok(root, 'verify', '--signed');
  assert.match(verified.stdout, /PASS {2}opurom-ui@0\.1\.0/);
  assert.match(verified.stdout, /PASS {2}opurom-lock|PASS {2}opurom\.lock/);
  assert.match(verified.stdout, /3\/3 checks passed/);
});

test('sign is idempotent and never prints key material', (t) => {
  const root = seededProject(t);
  const first = ok(root, 'sign');
  const second = ok(root, 'sign');
  assert.match(first.stdout, /new keypair created/);
  assert.doesNotMatch(second.stdout, /new keypair created/);
  assert.match(second.stdout, /signed 7 files with opurom\.pub/);
  assert.doesNotMatch(`${first.stdout}${first.stderr}`, /PRIVATE KEY/);
  assert.doesNotMatch(`${second.stdout}${second.stderr}`, /PRIVATE KEY/);
  assert.ok(ok(root, 'verify', '--signed').stdout.includes('3/3 checks passed'));
});

test('verify --signed rejects a tampered file', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  const target = path.join(root, SIGNED_FILE);
  writeFileSync(target, `${readFileSync(target, 'utf8')}\nstate tampered = 0\n`);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature/);
  assert.match(result.output, /button\.opu/);
});

test('verify --signed rejects a missing signature', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  rmSync(path.join(root, `${SIGNED_FILE}.sig`));
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing signature/);
  assert.match(result.output, /button\.opu/);
});

test('verify --signed rejects a wrong public key', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  const other = seededProject(t);
  ok(other, 'sign');
  writeFileSync(
    path.join(root, 'keys', 'opurom.pub'),
    readFileSync(path.join(other, 'keys', 'opurom.pub')),
  );
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature/);
});

test('verify --signed rejects lock drift', (t) => {
  const root = seededProject(t);
  ok(root, 'sign');
  const lock = path.join(root, 'opurom.lock');
  writeFileSync(lock, `${readFileSync(lock, 'utf8')}\n`);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature: opurom\.lock\.sig/);
});

test('verify --signed without a keypair reports a missing public key', (t) => {
  const root = seededProject(t);
  const result = run(root, 'verify', '--signed');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing public key/);
});

test('verify without --signed checks hashes only', (t) => {
  const root = seededProject(t);
  const result = ok(root, 'verify');
  assert.match(result.stdout, /PASS {2}<manifest>/);
  assert.match(result.stdout, /3\/3 checks passed/);
  assert.doesNotMatch(result.stdout, /signed/);
});
