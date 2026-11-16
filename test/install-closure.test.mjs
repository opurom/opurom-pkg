import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import {
  makeProject,
  ok,
  readJson,
  runWithEnv,
  startRegistry,
  writeJson,
} from '../lib/helpers.mjs';

function writePackage(root, name, version, dependencies) {
  const relative = path.posix.join('registry', name, version);
  mkdirSync(path.join(root, relative), { recursive: true });
  const manifest = { name, version, files: ['opurom-pkg.json'] };
  if (dependencies !== undefined) manifest.dependencies = dependencies;
  writeJson(root, `${relative}/opurom-pkg.json`, manifest);
}

function publishRoot(t) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'demo-registry',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  writePackage(root, 'tree-a', '1.0.0', { 'tree-b': '>=1.0.0' });
  writePackage(root, 'tree-b', '1.0.0');
  writePackage(root, 'tree-b', '1.1.0');
  writePackage(root, 'tree-c', '1.0.0', { 'tree-b': '>=2.0.0' });
  return root;
}

function clientRoot(t) {
  const root = makeProject(t);
  ok(root, 'init', 'demo-app');
  return root;
}

function rawRequest(port, requestPath, method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, path: requestPath, method },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode, body: Buffer.concat(chunks) }),
        );
      },
    );
    request.on('error', reject);
    request.end();
  });
}

test('the registry lists package versions and 404s unknown names', async (t) => {
  const root = publishRoot(t);
  const { port } = await startRegistry(t, root);

  const listed = await rawRequest(port, '/packages/tree-b/');
  assert.equal(listed.status, 200);
  assert.deepEqual(JSON.parse(listed.body.toString('utf8')), {
    name: 'tree-b',
    versions: ['1.0.0', '1.1.0'],
  });

  const missing = await rawRequest(port, '/packages/tree-missing/');
  assert.equal(missing.status, 404);
  assert.match(missing.body.toString('utf8'), /not found/);

  const refused = await rawRequest(port, '/packages/tree-b/', 'PUT');
  assert.equal(refused.status, 405);
  assert.match(refused.body.toString('utf8'), /method not allowed/);
});

test('install fetches the transitive closure over loopback HTTP', async (t) => {
  const serverRoot = publishRoot(t);
  const { url } = await startRegistry(t, serverRoot);
  for (const spec of ['tree-a@1.0.0', 'tree-b@1.0.0', 'tree-b@1.1.0', 'tree-c@1.0.0']) {
    const published = runWithEnv(serverRoot, { Opurom_REGISTRY_URL: url }, 'publish', spec);
    assert.equal(published.status, 0, published.output);
  }

  const client = clientRoot(t);
  const installed = runWithEnv(client, { Opurom_REGISTRY_URL: url }, 'install', 'tree-a@1.0.0');
  assert.equal(installed.status, 0, installed.output);
  assert.match(installed.stdout, /installed tree-a@1\.0\.0 \(\d+ files\)/);
  assert.match(installed.stdout, /fetched transitive: tree-b@1\.1\.0/);
  assert.ok(existsSync(path.join(client, 'registry', 'tree-b', '1.1.0', 'opurom-pkg.json')));

  ok(client, 'lock');
  assert.deepEqual(
    readJson(client, 'opurom.lock').packages.map((pkg) => `${pkg.name}@${pkg.version}`),
    ['tree-a@1.0.0', 'tree-b@1.1.0'],
  );
  assert.match(ok(client, 'lock', '--check').stdout, /up to date \(2 packages\)/);
  assert.match(ok(client, 'verify').stdout, /3\/3 checks passed/);
});

test('install does not refetch a transitive package the local registry already satisfies', async (t) => {
  const serverRoot = publishRoot(t);
  const { url } = await startRegistry(t, serverRoot);
  for (const spec of ['tree-a@1.0.0', 'tree-b@1.0.0']) {
    const published = runWithEnv(serverRoot, { Opurom_REGISTRY_URL: url }, 'publish', spec);
    assert.equal(published.status, 0, published.output);
  }

  const client = clientRoot(t);
  const first = runWithEnv(client, { Opurom_REGISTRY_URL: url }, 'install', 'tree-b@1.0.0');
  assert.equal(first.status, 0, first.output);
  const second = runWithEnv(client, { Opurom_REGISTRY_URL: url }, 'install', 'tree-a@1.0.0');
  assert.equal(second.status, 0, second.output);
  assert.match(second.stdout, /installed tree-a@1\.0\.0/);
  assert.doesNotMatch(second.stdout, /fetched transitive/);

  ok(client, 'lock');
  assert.deepEqual(
    readJson(client, 'opurom.lock').packages.map((pkg) => `${pkg.name}@${pkg.version}`),
    ['tree-a@1.0.0', 'tree-b@1.0.0'],
  );
  assert.match(ok(client, 'lock', '--check').stdout, /up to date \(2 packages\)/);
});

test('install fails honestly when no remote version satisfies a transitive contract', async (t) => {
  const serverRoot = publishRoot(t);
  const { url } = await startRegistry(t, serverRoot);
  for (const spec of ['tree-c@1.0.0', 'tree-b@1.0.0']) {
    const published = runWithEnv(serverRoot, { Opurom_REGISTRY_URL: url }, 'publish', spec);
    assert.equal(published.status, 0, published.output);
  }

  const client = clientRoot(t);
  const installed = runWithEnv(client, { Opurom_REGISTRY_URL: url }, 'install', 'tree-c@1.0.0');
  assert.notEqual(installed.status, 0);
  assert.match(installed.output, /no remote version of tree-b satisfies >=2\.0\.0/);
  assert.deepEqual(readJson(client, 'opurom.json').dependencies, {});
  assert.deepEqual(readJson(client, 'opurom.lock').packages, []);
});
