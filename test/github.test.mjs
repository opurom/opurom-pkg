import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {
  ok,
  runWithEnvAsync,
  seededProject,
  startGithubMock,
  writeJson,
} from '../lib/helpers.mjs';
import { closeServer, listenLoopback } from '../lib/registry.mjs';
import {
  MAX_ASSET_BYTES,
  assetNames,
  parseAssetName,
  parseTag,
  releaseBody,
} from '../lib/github-registry.mjs';
import {
  MANIFEST_NAME,
  createPackageArchive,
  encodeZip,
  sha256,
} from '../lib/package-archive.mjs';
import { loadOrCreateKeypair, signBytes } from '../lib/signing.mjs';

const REPOSITORY = 'opurom/opurom-pkg';
const NAME = 'opurom-extra';
const VERSION = '2.0.0';

function envFor(mock, token = randomBytes(16).toString('hex')) {
  return { OPUROM_GITHUB_API_URL: mock.url, OPR_GITHUB_TOKEN: token };
}

function extraPackage(root) {
  const directory = path.join(root, 'registry', NAME, VERSION);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, 'extra.opu'), `state ${NAME} = 1\n`);
  writeJson(root, path.join('registry', NAME, VERSION, 'opurom-pkg.json'), {
    name: NAME,
    version: VERSION,
    files: ['extra.opu', 'opurom-pkg.json'],
  });
}

function archiveFor(root) {
  const directory = path.join(root, 'registry', NAME, VERSION);
  const metadata = JSON.parse(readFileSync(path.join(directory, 'opurom-pkg.json'), 'utf8'));
  const files = metadata.files
    .map((relative) => ({ path: relative, bytes: readFileSync(path.join(directory, relative)) }))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return createPackageArchive({ name: NAME, version: VERSION, files });
}

function signedArchive(root) {
  const { privateKey } = loadOrCreateKeypair(root);
  const archive = archiveFor(root);
  const names = assetNames(NAME, VERSION);
  return {
    privateKey,
    archive,
    signature: signBytes(privateKey, names.archive, archive),
    digest: sha256(archive),
    names,
  };
}

function copyPublicKey(publisher, client) {
  mkdirSync(path.join(client, 'keys'), { recursive: true });
  cpSync(
    path.join(publisher, 'keys', 'opurom.pub'),
    path.join(client, 'keys', 'opurom.pub'),
  );
}

function copyOtherPublicKey(client) {
  const other = path.join(client, '.other-key');
  mkdirSync(other, { recursive: true });
  loadOrCreateKeypair(other);
  mkdirSync(path.join(client, 'keys'), { recursive: true });
  cpSync(path.join(other, 'keys', 'opurom.pub'), path.join(client, 'keys', 'opurom.pub'));
}

async function seedRelease(mock, token, releaseData) {
  const {
    name = NAME,
    version = VERSION,
    archive,
    signature,
    digest,
    includeSignature = true,
  } = releaseData;
  const names = assetNames(name, version);
  const base = `${mock.url}/repos/${REPOSITORY}/releases`;
  const headers = {
    authorization: `Bearer ${token}`,
    'user-agent': 'opurom-pkg-test',
    accept: 'application/vnd.github+json',
  };
  const created = await fetch(base, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({
      tag_name: names.tag,
      name: `OPUROM ${name}@${version}`,
      body: releaseBody(name, version, names.archive, digest),
      draft: false,
      prerelease: false,
    }),
  });
  assert.equal(created.status, 201, `create release returned ${created.status}`);
  const release = await created.json();
  const upload = async (assetName, bytes) => {
    const response = await fetch(
      `${base}/${release.id}/assets?name=${encodeURIComponent(assetName)}`,
      {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/octet-stream' },
        body: bytes,
      },
    );
    assert.equal(response.status, 201, `upload ${assetName} returned ${response.status}`);
    await response.arrayBuffer();
  };
  await upload(names.archive, archive);
  if (includeSignature) await upload(names.signature, signature);
  return release;
}

test('asset names encode exact versions and reject traversal', async (t) => {
  const names = assetNames('opurom-ui', '0.1.0');
  assert.deepEqual(names, {
    tag: 'opurom-pkg-opurom-ui-0.1.0',
    archive: 'opurom-pkg-opurom-ui-0.1.0.zip',
    signature: 'opurom-pkg-opurom-ui-0.1.0.zip.sig',
  });
  assert.equal(parseAssetName(names.archive).tag, names.tag);
  assert.equal(parseTag(names.tag).version, '0.1.0');
  assert.equal(parseAssetName(`../${names.archive}`), null);
  assert.throws(() => assetNames('../evil', '0.1.0'));

  const root = seededProject(t);
  const mock = await startGithubMock(t);
  const result = await runWithEnvAsync(
    root,
    envFor(mock),
    'search',
    '--github',
    '../evil',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid GitHub repository/);
});

test('mock publish, search and install round trip over real TCP', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const token = randomBytes(16).toString('hex');
  const env = envFor(mock, token);

  const published = await runWithEnvAsync(
    publisher,
    env,
    'publish',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.equal(published.status, 0, published.output);
  assert.match(published.stdout, /published opurom-extra@2\.0\.0/);
  assert.match(
    published.stdout,
    /assets=opurom-pkg-opurom-extra-2\.0\.0\.zip,opurom-pkg-opurom-extra-2\.0\.0\.zip\.sig/,
  );
  assert.ok(!published.output.includes(token), 'publish output must not contain the token');

  const searched = await runWithEnvAsync(
    publisher,
    env,
    'search',
    '--github',
    REPOSITORY,
    NAME,
  );
  assert.equal(searched.status, 0, searched.output);
  assert.match(searched.stdout, /opurom-extra@2\.0\.0/);
  assert.match(searched.stdout, /asset=opurom-pkg-opurom-extra-2\.0\.0\.zip/);
  assert.ok(!searched.output.includes(token), 'search output must not contain the token');

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const installed = await runWithEnvAsync(
    client,
    env,
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.equal(installed.status, 0, installed.output);
  assert.equal(
    readFileSync(path.join(client, 'registry', NAME, VERSION, 'extra.opu'), 'utf8'),
    `state ${NAME} = 1\n`,
  );
  assert.match(ok(client, 'verify').stdout, /4\/4 checks passed/);
  assert.ok(!installed.output.includes(token), 'install output must not contain the token');
});

test('publish SKIPs without a token and creates no release', async (t) => {
  const mock = await startGithubMock(t);
  const root = seededProject(t);
  extraPackage(root);
  const env = { OPUROM_GITHUB_API_URL: mock.url, OPR_GITHUB_TOKEN: '' };

  const result = await runWithEnvAsync(
    root,
    env,
    'publish',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.equal(result.status, 0, result.output);
  assert.match(result.stdout, /^SKIP missing OPR_GITHUB_TOKEN; no GitHub Release was created/);
  assert.doesNotMatch(result.output, /published/);

  const search = await runWithEnvAsync(root, env, 'search', '--github', REPOSITORY);
  assert.equal(search.status, 0, search.output);
  assert.match(search.stdout, /no signed packages found/);
});

test('a closed local API prints SKIP network unavailable', async (t) => {
  const mock = await startGithubMock(t);
  const url = mock.url;
  await closeServer(mock.server);
  const root = seededProject(t);
  const result = await runWithEnvAsync(
    root,
    { OPUROM_GITHUB_API_URL: url, OPR_GITHUB_TOKEN: '' },
    'search',
    '--github',
    REPOSITORY,
  );
  assert.equal(result.status, 0, result.output);
  assert.match(result.stdout, /^SKIP network unavailable: /);
  assert.match(result.stdout, /ECONNREFUSED|fetch failed|connection/i);
});

test('install rejects a tampered archive before extraction', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const signed = signedArchive(publisher);
  const tampered = Buffer.from(signed.archive);
  tampered[tampered.length - 1] ^= 0xff;
  const token = randomBytes(16).toString('hex');
  await seedRelease(mock, token, {
    archive: tampered,
    signature: signed.signature,
    digest: sha256(tampered),
  });

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const result = await runWithEnvAsync(
    client,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature/);
  assert.ok(!existsSync(path.join(client, 'registry', NAME, VERSION, 'extra.opu')));
});

test('install rejects a signature made by a different key', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const signed = signedArchive(publisher);
  const token = randomBytes(16).toString('hex');
  await seedRelease(mock, token, signed);

  const client = seededProject(t);
  copyOtherPublicKey(client);
  const result = await runWithEnvAsync(
    client,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid signature/);
});

test('install rejects release and per-file sha256 mismatches', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const signed = signedArchive(publisher);
  const token = randomBytes(16).toString('hex');
  await seedRelease(mock, token, { ...signed, digest: 'f'.repeat(64) });

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  let result = await runWithEnvAsync(
    client,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /sha256 mismatch: opurom-pkg-opurom-extra-2\.0\.0\.zip/);

  const version = '2.0.1';
  const directory = path.join(publisher, 'registry', NAME, VERSION);
  const extra = readFileSync(path.join(directory, 'extra.opu'));
  const metadata = readFileSync(path.join(directory, 'opurom-pkg.json'));
  const manifest = {
    format: 1,
    name: NAME,
    version,
    files: [
      { path: 'extra.opu', sha256: 'e'.repeat(64) },
      { path: 'opurom-pkg.json', sha256: sha256(metadata) },
    ],
  };
  const badArchive = encodeZip([
    { name: MANIFEST_NAME, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    { name: 'extra.opu', bytes: extra },
    { name: 'opurom-pkg.json', bytes: metadata },
  ]);
  const names = assetNames(NAME, version);
  await seedRelease(mock, token, {
    version,
    archive: badArchive,
    signature: signBytes(signed.privateKey, names.archive, badArchive),
    digest: sha256(badArchive),
  });

  const secondClient = seededProject(t);
  copyPublicKey(publisher, secondClient);
  result = await runWithEnvAsync(
    secondClient,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${version}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /sha256 mismatch: extra\.opu/);
});

test('install rejects a missing detached signature asset', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const signed = signedArchive(publisher);
  const token = randomBytes(16).toString('hex');
  await seedRelease(mock, token, { ...signed, includeSignature: false });

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const result = await runWithEnvAsync(
    client,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /missing signature asset/);
  assert.ok(!existsSync(path.join(client, 'registry', NAME, VERSION, 'extra.opu')));
});

test('install rejects bounded-size violations', async (t) => {
  const first = assetNames(NAME, VERSION);
  const second = assetNames(NAME, '2.0.1');
  const digest = 'f'.repeat(64);
  const releases = new Map([
    [first.tag, { tag: first.tag, names: first, archiveId: 1, signatureId: 2, size: MAX_ASSET_BYTES + 1 }],
    [second.tag, { tag: second.tag, names: second, archiveId: 11, signatureId: 12, size: 1 }],
  ]);
  const sendJson = (response, status, value) => {
    const body = Buffer.from(JSON.stringify(value));
    response.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length });
    response.end(body);
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const tagMatch = /^\/repos\/opurom\/opurom-pkg\/releases\/tags\/(.+)$/.exec(url.pathname);
    if (request.method === 'GET' && tagMatch) {
      const release = releases.get(tagMatch[1]);
      if (!release) {
        sendJson(response, 404, { message: 'not found' });
        return;
      }
      sendJson(response, 200, {
        id: 1,
        tag_name: release.tag,
        name: release.tag,
        body: releaseBody(NAME, release.tag.endsWith('2.0.1') ? '2.0.1' : VERSION, release.names.archive, digest),
        html_url: `https://github.com/${REPOSITORY}/releases/tag/${release.tag}`,
        assets: [
          { id: release.archiveId, name: release.names.archive, size: release.size },
          { id: release.signatureId, name: release.names.signature, size: 64 },
        ],
      });
      return;
    }
    const assetMatch = /\/releases\/assets\/(\d+)$/.exec(url.pathname);
    if (request.method === 'GET' && assetMatch) {
      const id = Number(assetMatch[1]);
      if (id === 11) {
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        for (let index = 0; index < 65; index += 1) response.write(Buffer.alloc(65536));
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': '64' });
      response.end(Buffer.alloc(64));
      return;
    }
    sendJson(response, 404, { message: 'not found' });
  });
  const port = await listenLoopback(server, 0);
  t.after(() => closeServer(server));
  const root = seededProject(t);
  const env = { OPUROM_GITHUB_API_URL: `http://127.0.0.1:${port}`, OPR_GITHUB_TOKEN: '' };

  let result = await runWithEnvAsync(
    root,
    env,
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /exceeds bounded size/);

  result = await runWithEnvAsync(
    root,
    env,
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@2.0.1`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /response exceeds/);
});

test('install rejects traversal inside a signed archive', async (t) => {
  const mock = await startGithubMock(t);
  const publisher = seededProject(t);
  extraPackage(publisher);
  const { privateKey } = loadOrCreateKeypair(publisher);
  const evil = Buffer.from('state evil = 1\n');
  const manifest = {
    format: 1,
    name: NAME,
    version: VERSION,
    files: [{ path: '../evil.opu', sha256: sha256(evil) }],
  };
  const archive = encodeZip([
    { name: MANIFEST_NAME, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    { name: '../evil.opu', bytes: evil },
  ]);
  const names = assetNames(NAME, VERSION);
  const token = randomBytes(16).toString('hex');
  await seedRelease(mock, token, {
    archive,
    signature: signBytes(privateKey, names.archive, archive),
    digest: sha256(archive),
  });

  const client = seededProject(t);
  copyPublicKey(publisher, client);
  const result = await runWithEnvAsync(
    client,
    envFor(mock, token),
    'install',
    '--github',
    REPOSITORY,
    `${NAME}@${VERSION}`,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /unsafe archive path/);
  assert.ok(!existsSync(path.join(client, 'evil.opu')));
  assert.ok(!existsSync(path.join(client, 'registry', NAME, VERSION, 'extra.opu')));
});
