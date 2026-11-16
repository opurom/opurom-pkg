import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeProject, runWithEnvAsync, startGithubMock, writeJson } from '../lib/helpers.mjs';
import { loadOrCreateKeypair } from '../lib/signing.mjs';

const REPOSITORY = 'opurom/marketplace';
const TOKEN = 'test-token';
const METADATA = {
  description: 'A discovery package',
  keywords: ['plugin', 'camera'],
  license: 'MIT',
  capabilities: ['camera.takePhoto'],
};

function publisherRoot(t) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'market-publisher',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  loadOrCreateKeypair(root);
  return root;
}

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

function envFor(mock) {
  return { Opurom_GITHUB_API_URL: mock.url, OPR_GITHUB_TOKEN: TOKEN };
}

async function publish(root, env, spec) {
  const result = await runWithEnvAsync(root, env, 'publish', '--github', REPOSITORY, spec);
  assert.equal(result.status, 0, result.output);
  return result;
}

async function rawRelease(mock, tag, assets) {
  const created = await fetch(`${mock.url}/repos/opurom/marketplace/releases`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tag_name: tag, body: 'discovery fixture' }),
  });
  const release = await created.json();
  for (const [name, bytes] of assets) {
    const uploaded = await fetch(
      `${mock.url}/repos/opurom/marketplace/releases/${release.id}/assets?name=${encodeURIComponent(name)}`,
      { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: bytes },
    );
    assert.equal(uploaded.status, 201, await uploaded.text());
  }
  return release;
}

test('search outputs the fact table and a machine-readable --json view', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const env = envFor(mock);
  writePackage(publisher, 'market-a', '0.1.0', METADATA);
  writePackage(publisher, 'market-a', '0.2.0', METADATA);
  writePackage(publisher, 'market-b', '1.0.0');
  for (const spec of ['market-a@0.1.0', 'market-a@0.2.0', 'market-b@1.0.0']) {
    await publish(publisher, env, spec);
  }

  const table = await runWithEnvAsync(publisher, { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY);
  assert.equal(table.status, 0, table.output);
  assert.match(table.stdout, /NAME\s+LATEST\s+DESCRIPTION\s+SIGNED/);
  assert.match(table.stdout, /market-a\s+0\.2\.0\s+A discovery package\s+2\/2/);
  assert.match(table.stdout, /market-b\s+1\.0\.0\s+-\s+1\/1/);

  const filtered = await runWithEnvAsync(publisher, { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY, 'market-a');
  assert.equal(filtered.status, 0, filtered.output);
  assert.match(filtered.stdout, /market-a/);
  assert.doesNotMatch(filtered.stdout, /market-b/);

  const json = await runWithEnvAsync(publisher, { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY, '--json');
  assert.equal(json.status, 0, json.output);
  assert.equal(json.stdout.trim().split('\n').length, 1);
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.repository, REPOSITORY);
  assert.equal(parsed.truncated, false);
  assert.deepEqual(parsed.packages, [
    {
      name: 'market-a',
      latest: '0.2.0',
      latestTag: 'opurom-pkg-market-a-0.2.0',
      description: 'A discovery package',
      signed: '2/2',
      downloadVolume: 'n/a (no telemetry)',
    },
    {
      name: 'market-b',
      latest: '1.0.0',
      latestTag: 'opurom-pkg-market-b-1.0.0',
      description: '-',
      signed: '1/1',
      downloadVolume: 'n/a (no telemetry)',
    },
  ]);
});

test('SIGNED is a listing fact: a release without a signature changes it, not a verification', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const env = envFor(mock);
  writePackage(publisher, 'market-a', '0.1.0', METADATA);
  writePackage(publisher, 'market-a', '0.2.0', METADATA);
  for (const spec of ['market-a@0.1.0', 'market-a@0.2.0']) await publish(publisher, env, spec);
  await rawRelease(mock, 'opurom-pkg-market-a-0.3.0', [
    ['opurom-pkg-market-a-0.3.0.zip', Buffer.from('unsigned archive')],
    [
      'opurom-pkg-market-a-0.3.0.manifest.json',
      Buffer.from(JSON.stringify({ name: 'market-a', version: '0.3.0', files: [], ...METADATA })),
    ],
  ]);

  const table = await runWithEnvAsync(publisher, { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY, 'market-a');
  assert.equal(table.status, 0, table.output);
  assert.match(table.stdout, /market-a\s+0\.3\.0\s+-\s+2\/3/);
  assert.doesNotMatch(table.stdout, /verified/i);
});

test('info lists every version, dependencies and the separate fact panel', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const env = envFor(mock);
  writePackage(publisher, 'market-a', '0.1.0', METADATA);
  writePackage(publisher, 'market-a', '0.2.0', {
    ...METADATA,
    dependencies: { 'market-b': '0.1.0' },
  });
  writePackage(publisher, 'market-b', '0.1.0');
  await publish(publisher, env, 'market-a@0.1.0');
  await publish(publisher, env, 'market-a@0.2.0');
  await publish(publisher, env, 'market-b@0.1.0');
  await rawRelease(mock, 'opurom-pkg-market-a-0.3.0', [
    ['opurom-pkg-market-a-0.3.0.zip', Buffer.from('unsigned archive')],
    [
      'opurom-pkg-market-a-0.3.0.manifest.json',
      Buffer.from(JSON.stringify({ name: 'market-a', version: '0.3.0', files: [], ...METADATA })),
    ],
  ]);

  const info = await runWithEnvAsync(publisher, { Opurom_GITHUB_API_URL: mock.url }, 'info', '--github', REPOSITORY, 'market-a');
  assert.equal(info.status, 0, info.output);
  assert.match(info.stdout, /VERSION\s+TAG\s+PUBLISHED\s+DEPENDENCIES\s+SIGNED/);
  assert.match(info.stdout, /0\.3\.0\s+opurom-pkg-market-a-0\.3\.0\s+\S+\s+-\s+no/);
  assert.match(info.stdout, /0\.2\.0\s+opurom-pkg-market-a-0\.2\.0\s+\S+\s+market-b@0\.1\.0\s+yes/);
  assert.match(info.stdout, /FACTS/);
  assert.match(info.stdout, /versions\s+3/);
  assert.match(info.stdout, /signatures\s+2\/3/);
  assert.match(info.stdout, /metadata\s+4\/4/);
  assert.match(info.stdout, /download volume\s+n\/a \(no telemetry\)/);
  assert.doesNotMatch(info.stdout, /truncated:/);
});

test('a full release page is reported as truncated, never silently cut', async (t) => {
  const mock = await startGithubMock(t);
  const assets = [];
  for (let patch = 1; patch <= 100; patch += 1) {
    const version = `0.0.${patch}`;
    assets.push([`opurom-pkg-market-many-${version}.zip`, Buffer.from(`archive ${version}`)]);
  }
  // Plus one release beyond the page, which cannot be discovered in one request.
  await rawRelease(mock, 'opurom-pkg-market-many-0.0.101', [
    ['opurom-pkg-market-many-0.0.101.zip', Buffer.from('archive 101')],
  ]);
  for (const [name, bytes] of assets) {
    const version = name.match(/(\d+\.\d+\.\d+)\.zip$/)[1];
    await rawRelease(mock, `opurom-pkg-market-many-${version}`, [[name, bytes]]);
  }

  const json = await runWithEnvAsync(publisherRoot(t), { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY, '--json');
  assert.equal(json.status, 0, json.output);
  assert.equal(JSON.parse(json.stdout).truncated, true);

  const table = await runWithEnvAsync(publisherRoot(t), { Opurom_GITHUB_API_URL: mock.url }, 'search', '--github', REPOSITORY, 'market-many');
  assert.equal(table.status, 0, table.output);
  assert.match(table.stdout, /truncated: release listing is limited to one page/);
});

test('discovery manifest fields are format-checked and never interpreted', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = publisherRoot(t);
  const env = envFor(mock);

  writePackage(publisher, 'market-bad', '0.1.0', { keywords: 'not-an-array' });
  let result = await runWithEnvAsync(publisher, env, 'publish', '--github', REPOSITORY, 'market-bad@0.1.0');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /keywords must be an array of strings/);

  writePackage(publisher, 'market-bad', '0.1.0', { capabilities: ['no-dot'] });
  result = await runWithEnvAsync(publisher, env, 'publish', '--github', REPOSITORY, 'market-bad@0.1.0');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /capabilities must be dotted names/);

  writePackage(publisher, 'market-bad', '0.1.0', { description: 42 });
  result = await runWithEnvAsync(publisher, env, 'publish', '--github', REPOSITORY, 'market-bad@0.1.0');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /description must be a non-empty string/);
});
