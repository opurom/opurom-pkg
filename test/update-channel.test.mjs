import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  makeProject,
  ok,
  readJson,
  runWithEnv,
  runWithEnvAsync,
  seededProject,
  startGithubMock,
  writeJson,
} from '../lib/helpers.mjs';
import { loadOrCreateKeypair, signBytes } from '../lib/signing.mjs';
import { sha256 } from '../lib/package-archive.mjs';

const REPOSITORY = 'ota/updates';
const BUNDLE = 'opurom-framework-0.2.0.tar.gz';
const BUNDLE_BYTES = Buffer.from('opurom framework bundle bytes\n');

function publisherRoot(t) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'ota-publisher',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  loadOrCreateKeypair(root);
  return root;
}

function manifestJson(latest, tag, bundleName, digest) {
  return JSON.stringify(
    { channel: 'stable', version: 1, latest, tag, bundle: bundleName, bundleSha256: digest },
    null,
    2,
  );
}

function copyPublicKey(publisher, client) {
  mkdirSync(path.join(client, 'keys'), { recursive: true });
  copyFileSync(path.join(publisher, 'keys', 'opurom.pub'), path.join(client, 'keys', 'opurom.pub'));
}

function updateEnv(mock) {
  return { Opurom_GITHUB_API_URL: mock.url };
}

async function createRelease(mock, tag, manifest, signature, bundleName, bundleBytes) {
  const created = await fetch(`${mock.url}/repos/ota/updates/releases`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tag_name: tag, body: 'ota channel release' }),
  });
  const release = await created.json();
  assert.equal(created.status, 201, JSON.stringify(release));
  for (const [name, bytes] of [
    ['update-channel.json', manifest],
    ['update-channel.json.sig', signature],
    [bundleName, bundleBytes],
  ]) {
    const uploaded = await fetch(
      `${mock.url}/repos/ota/updates/releases/${release.id}/assets?name=${encodeURIComponent(name)}`,
      { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: bytes },
    );
    assert.equal(uploaded.status, 201, await uploaded.text());
  }
  return release;
}

function signedPublisherManifest(publisher, latest, tag, bundleName, digest) {
  const manifest = Buffer.from(manifestJson(latest, tag, bundleName, digest));
  writeFileSync(path.join(publisher, 'update-channel.json'), manifest);
  ok(publisher, 'channel-sign', 'update-channel.json');
  return {
    manifest,
    signature: readFileSync(path.join(publisher, 'update-channel.json.sig')),
  };
}

test('channel-sign and channel-verify round trip and reject tampering', (t) => {
  const publisher = publisherRoot(t);
  writeFileSync(path.join(publisher, 'update-channel.json'), 'channel: stable\n');
  ok(publisher, 'channel-sign', 'update-channel.json');
  assert.match(ok(publisher, 'channel-verify', 'update-channel.json').stdout, /PASS/);

  writeFileSync(path.join(publisher, 'update-channel.json'), 'channel: stable\ntampered\n');
  const tampered = runWithEnv(publisher, {}, 'channel-verify', 'update-channel.json');
  assert.notEqual(tampered.status, 0);
  assert.match(tampered.output, /invalid signature: update-channel\.json\.sig/);

  const unsigned = makeProject(t);
  writeJson(unsigned, 'opurom.json', {
    name: 'ota-publisher',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  loadOrCreateKeypair(unsigned);
  writeFileSync(path.join(unsigned, 'update-channel.json'), 'channel: stable\n');
  const missing = runWithEnv(unsigned, {}, 'channel-verify', 'update-channel.json');
  assert.notEqual(missing.status, 0);
  assert.match(missing.output, /missing signature: update-channel\.json\.sig/);
});

test('update check reports a newer signed release', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(BUNDLE_BYTES);
  const { manifest, signature } = signedPublisherManifest(publisher, '0.2.0', 'v0.2.0', BUNDLE, digest);
  await createRelease(mock, 'v0.2.0', manifest, signature, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const checked = await runWithEnvAsync(client, updateEnv(mock), 'update', 'check', '--github', REPOSITORY, '--current', '0.1.0');
  assert.equal(checked.status, 0, checked.output);
  assert.match(checked.stdout, /LATEST\s+CURRENT\s+TAG\s+BUNDLE\s+SHA256/);
  assert.match(checked.stdout, /0\.2\.0\s+0\.1\.0\s+v0\.2\.0\s+opurom-framework-0\.2\.0\.tar\.gz/);
  assert.ok(checked.stdout.includes(digest));
});

test('update check reports already up to date for current and newer versions', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(BUNDLE_BYTES);
  const { manifest, signature } = signedPublisherManifest(publisher, '0.2.0', 'v0.2.0', BUNDLE, digest);
  await createRelease(mock, 'v0.2.0', manifest, signature, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  for (const current of ['0.2.0', '9.9.9']) {
    const checked = await runWithEnvAsync(client, updateEnv(mock), 'update', 'check', '--github', REPOSITORY, '--current', current);
    assert.equal(checked.status, 0, checked.output);
    assert.equal(checked.stdout, 'already up to date\n');
  }
});

test('update check rejects a signature that does not cover the manifest', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(BUNDLE_BYTES);
  const manifest = Buffer.from(manifestJson('0.2.0', 'v0.2.0', BUNDLE, digest));
  const { privateKey } = loadOrCreateKeypair(publisher);
  const wrong = signBytes(privateKey, 'update-channel.json', Buffer.from('other bytes'));
  await createRelease(mock, 'v0.2.0', manifest, wrong, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const checked = await runWithEnvAsync(client, updateEnv(mock), 'update', 'check', '--github', REPOSITORY, '--current', '0.1.0');
  assert.notEqual(checked.status, 0);
  assert.match(checked.output, /invalid signature: update-channel\.json\.sig/);
});

test('update check rejects a manifest that disagrees with its release tag', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(BUNDLE_BYTES);
  const { manifest, signature } = signedPublisherManifest(publisher, '0.9.0', 'v0.2.0', BUNDLE, digest);
  await createRelease(mock, 'v0.2.0', manifest, signature, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const checked = await runWithEnvAsync(client, updateEnv(mock), 'update', 'check', '--github', REPOSITORY, '--current', '0.1.0');
  assert.notEqual(checked.status, 0);
  assert.match(checked.output, /does not match release tag v0\.2\.0/);
});

test('update fetch writes the verified bundle, manifest and signature', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(BUNDLE_BYTES);
  const { manifest, signature } = signedPublisherManifest(publisher, '0.2.0', 'v0.2.0', BUNDLE, digest);
  await createRelease(mock, 'v0.2.0', manifest, signature, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const fetched = await runWithEnvAsync(client, updateEnv(mock), 'update', 'fetch', '--github', REPOSITORY, '--current', '0.1.0', '--out', 'updates');
  assert.equal(fetched.status, 0, fetched.output);
  assert.match(fetched.stdout, /fetched 0\.2\.0 bundle opurom-framework-0\.2\.0\.tar\.gz \(\d+ bytes\) to updates/);
  assert.ok(existsSync(path.join(client, 'updates', BUNDLE)));
  assert.ok(existsSync(path.join(client, 'updates', 'update-channel.json')));
  assert.ok(existsSync(path.join(client, 'updates', 'update-channel.json.sig')));
  assert.deepEqual(readFileSync(path.join(client, 'updates', BUNDLE)), BUNDLE_BYTES);
  assert.deepEqual(readFileSync(path.join(client, 'updates', 'update-channel.json')), manifest);
  // The update channel never touches the project lock or registry.
  assert.match(ok(client, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('update fetch refuses a bundle whose digest mismatches and writes nothing', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const digest = sha256(Buffer.from('expected bundle bytes\n'));
  const { manifest, signature } = signedPublisherManifest(publisher, '0.2.0', 'v0.2.0', BUNDLE, digest);
  await createRelease(mock, 'v0.2.0', manifest, signature, BUNDLE, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const fetched = await runWithEnvAsync(client, updateEnv(mock), 'update', 'fetch', '--github', REPOSITORY, '--current', '0.1.0', '--out', 'updates');
  assert.notEqual(fetched.status, 0);
  assert.match(fetched.output, /sha256 mismatch: opurom-framework-0\.2\.0\.tar\.gz/);
  assert.equal(existsSync(path.join(client, 'updates')), false);
});

test('update fetch refuses downgrades unless explicitly allowed', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const oldDigest = sha256(BUNDLE_BYTES);
  const oldBundle = 'opurom-framework-0.1.0.tar.gz';
  const { manifest: oldManifest, signature: oldSignature } = signedPublisherManifest(publisher, '0.1.0', 'v0.1.0', oldBundle, oldDigest);
  await createRelease(mock, 'v0.1.0', oldManifest, oldSignature, oldBundle, BUNDLE_BYTES);

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const refused = await runWithEnvAsync(client, updateEnv(mock), 'update', 'fetch', '--github', REPOSITORY, '--current', '0.3.0', '--version', '0.1.0', '--out', 'updates');
  assert.notEqual(refused.status, 0);
  assert.match(refused.output, /refusing downgrade: requested 0\.1\.0 < current 0\.3\.0/);
  assert.equal(existsSync(path.join(client, 'updates')), false);

  const allowed = await runWithEnvAsync(client, updateEnv(mock), 'update', 'fetch', '--github', REPOSITORY, '--current', '0.3.0', '--version', '0.1.0', '--out', 'updates', '--allow-downgrade');
  assert.equal(allowed.status, 0, allowed.output);
  assert.match(allowed.stdout, /fetched 0\.1\.0 bundle/);

  const latest = await runWithEnvAsync(client, updateEnv(mock), 'update', 'fetch', '--github', REPOSITORY, '--current', '0.3.0', '--out', 'rollback');
  assert.notEqual(latest.status, 0);
  assert.match(latest.output, /refusing downgrade: requested 0\.1\.0 < current 0\.3\.0/);
});

test('update check degrades to SKIP when the channel is unreachable', async (t) => {
  const client = seededProject(t);
  const unreachable = await runWithEnvAsync(client, { Opurom_GITHUB_API_URL: 'http://127.0.0.1:1' }, 'update', 'check', '--github', REPOSITORY, '--current', '0.1.0');
  assert.equal(unreachable.status, 0);
  assert.match(unreachable.stdout, /^SKIP network unavailable: /);
});
