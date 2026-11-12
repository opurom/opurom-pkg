import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {
  makeProject,
  ok,
  run,
  runWithEnv,
  runWithEnvAsync,
  seededProject,
  spawnRegistry,
  startRegistry,
  writeJson,
} from '../lib/helpers.mjs';

// Raw HTTP client: the URL path is sent verbatim so traversal reaches the server.
function rawGet(port, requestPath, method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, path: requestPath, method, agent: false },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    request.on('error', reject);
    request.end();
  });
}

function rawPut(port, requestPath, body, declaredSha256) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(body, 'utf8');
    const request = http.request(
      {
        host: '127.0.0.1',
        port,
        path: requestPath,
        method: 'PUT',
        agent: false,
        headers: {
          'content-length': payload.length,
          'x-content-sha256': declaredSha256,
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode, body: Buffer.concat(chunks) }),
        );
      },
    );
    request.on('error', reject);
    request.write(payload);
    request.end();
  });
}

function extraPackage(root, name, version) {
  const directory = path.join(root, 'registry', name, version);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, 'extra.opu'), `state ${name} = 1\n`);
  writeJson(root, path.join('registry', name, version, 'opurom-pkg.json'), {
    name,
    version,
    files: ['extra.opu', 'opurom-pkg.json'],
  });
}

test('registry serves a package file with its sha256', async (t) => {
  const root = seededProject(t);
  const { port } = await startRegistry(t, root);
  const response = await rawGet(port, '/packages/opurom-ui/0.1.0/button.opu');
  assert.equal(response.status, 200);
  const expected = createHash('sha256')
    .update(readFileSync(path.join(root, 'registry', 'opurom-ui', '0.1.0', 'button.opu')))
    .digest('hex');
  assert.equal(response.headers['x-content-sha256'], expected);
  assert.equal(
    createHash('sha256').update(response.body).digest('hex'),
    expected,
  );
});

test('registry returns 404 for an unknown package file', async (t) => {
  const root = seededProject(t);
  const { port } = await startRegistry(t, root);
  const response = await rawGet(port, '/packages/opurom-ui/0.1.0/missing.opu');
  assert.equal(response.status, 404);
  assert.match(response.body.toString('utf8'), /not found/);
});

test('registry rejects traversal attempts', async (t) => {
  const root = seededProject(t);
  const { port } = await startRegistry(t, root);
  for (const attempt of [
    '/packages/opurom-ui/0.1.0/../../../opurom.lock',
    '/packages/opurom-ui/0.1.0/%2e%2e/%2e%2e/opurom.lock',
    '/packages/opurom-ui/0.1.0/..%2f..%2fopurom.lock',
  ]) {
    const response = await rawGet(port, attempt);
    assert.ok(
      response.status === 400 || response.status === 404,
      `${attempt} returned ${response.status}`,
    );
    assert.doesNotMatch(response.body.toString('utf8'), /"name"/);
  }
});

test('registry rejects an oversized request body', async (t) => {
  const root = seededProject(t);
  const { port } = await startRegistry(t, root);
  const oversized = Buffer.alloc(5 * 1024 * 1024, 0x61);
  const response = await new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '/packages/opurom-ui/0.1.0/oversized.opu',
        method: 'PUT',
        headers: { 'content-length': oversized.length },
      },
      (result) => {
        const chunks = [];
        result.on('data', (chunk) => chunks.push(chunk));
        result.on('end', () =>
          resolve({
            status: result.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    request.on('error', () => resolve({ status: 0, body: '' }));
    request.write(oversized);
    request.end();
  });
  assert.ok(response.status === 413 || response.status === 0, `status ${response.status}`);
  assert.ok(
    !existsSync(path.join(root, 'registry', 'opurom-ui', '0.1.0', 'oversized.opu')),
    'oversized body must not be written',
  );
});

test('publish and install round trip over real TCP', async (t) => {
  const serverRoot = seededProject(t);
  extraPackage(serverRoot, 'opurom-extra', '2.0.0');
  const { url } = await startRegistry(t, serverRoot);

  const published = runWithEnv(
    serverRoot,
    { OPUROM_REGISTRY_URL: url },
    'publish',
    'opurom-extra@2.0.0',
  );
  assert.equal(published.status, 0, published.output);
  assert.match(published.stdout, /published opurom-extra@2\.0\.0 \(2 files\)/);

  const clientRoot = seededProject(t);
  const installed = runWithEnv(
    clientRoot,
    { OPUROM_REGISTRY_URL: url },
    'install',
    'opurom-extra@2.0.0',
  );
  assert.equal(installed.status, 0, installed.output);
  assert.match(installed.stdout, /installed opurom-extra@2\.0\.0 \(2 files\)/);
  const installedFile = path.join(
    clientRoot,
    'registry',
    'opurom-extra',
    '2.0.0',
    'extra.opu',
  );
  assert.ok(existsSync(installedFile));
  assert.equal(readFileSync(installedFile, 'utf8'), 'state opurom-extra = 1\n');
  assert.match(ok(clientRoot, 'verify').stdout, /4\/4 checks passed/);
});

test('registry rejects a publish body whose declared digest does not match', async (t) => {
  const root = seededProject(t);
  const { port } = await startRegistry(t, root);
  const response = await rawPut(port, '/packages/opurom-ui/0.1.0/evil.opu', 'state evil = 1\n', 'a'.repeat(64));
  assert.equal(response.status, 400);
  assert.match(response.body.toString('utf8'), /integrity mismatch/);
  assert.ok(!existsSync(path.join(root, 'registry', 'opurom-ui', '0.1.0', 'evil.opu')));
});

test('install refuses a registry that advertises a wrong digest', async (t) => {
  const clientRoot = seededProject(t);
  const server = http.createServer((request, response) => {
    if (request.url.endsWith('/')) {
      response.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      response.end(
        JSON.stringify({
          name: 'opurom-extra',
          version: '2.0.0',
          files: [{ path: 'extra.opu', sha256: 'f'.repeat(64) }],
        }),
      );
      return;
    }
    response.writeHead(200, { 'x-content-sha256': 'f'.repeat(64), connection: 'close' });
    response.end('state extra = 1\n');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  );
  const port = server.address().port;

  const result = await runWithEnvAsync(
    clientRoot,
    { OPUROM_REGISTRY_URL: `http://127.0.0.1:${port}` },
    'install',
    'opurom-extra@2.0.0',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /digest mismatch/);
});

test('install rejects a file whose digest differs from the registry listing', async (t) => {
  const clientRoot = seededProject(t);
  const body = 'state extra = 1\n';
  const realDigest = createHash('sha256').update(body).digest('hex');
  const server = http.createServer((request, response) => {
    if (request.url.endsWith('/')) {
      response.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      response.end(
        JSON.stringify({
          name: 'opurom-extra',
          version: '2.0.0',
          // The listing advertises a digest the body does not have.
          files: [{ path: 'extra.opu', sha256: 'f'.repeat(64) }],
        }),
      );
      return;
    }
    response.writeHead(200, { 'x-content-sha256': realDigest, connection: 'close' });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  );
  const port = server.address().port;

  const result = await runWithEnvAsync(
    clientRoot,
    { OPUROM_REGISTRY_URL: `http://127.0.0.1:${port}` },
    'install',
    'opurom-extra@2.0.0',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /sha256 mismatch/);
  assert.ok(
    !existsSync(
      path.join(clientRoot, 'registry', 'opurom-extra', '2.0.0', 'extra.opu'),
    ),
    'a file that failed its integrity check must not be installed',
  );
});

test('install refuses a non-loopback registry host', (t) => {
  const root = seededProject(t);
  const result = runWithEnv(
    root,
    { OPUROM_REGISTRY_URL: 'http://example.com:4873' },
    'install',
    'opurom-ui@0.1.0',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.output, /non-loopback/);
});

test('registry server releases its port when it stops', async (t) => {
  const root = makeProject(t);
  const server = await spawnRegistry(root);
  t.after(() => server.stop());
  const response = await rawGet(server.port, '/packages/opurom-ui/0.1.0/button.opu');
  assert.equal(response.status, 200);
  await server.stop();
  // After the server stops the port must refuse new connections.
  await assert.rejects(
    new Promise((resolve, reject) => {
      const socket = net.connect(server.port, '127.0.0.1');
      socket.on('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.on('error', reject);
    }),
  );
});
