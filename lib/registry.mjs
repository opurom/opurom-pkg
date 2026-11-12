// Local mock package registry over loopback HTTP. Node builtins only.
// No TLS, no authentication, no remote hosts: a test fixture, not a marketplace.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';

export const MAX_BODY = 4 * 1024 * 1024;
const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
const VERSION_RE = /^\d+\.\d+\.\d+$/;

export class RegistryError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function isUnsafeSegment(segment) {
  return (
    segment === '' ||
    segment === '.' ||
    segment === '..' ||
    segment.includes('\0') ||
    segment.includes('/') ||
    segment.includes('\\')
  );
}

export function safeSegments(segments) {
  for (const segment of segments) {
    if (isUnsafeSegment(segment)) {
      throw new RegistryError(`unsafe path segment: ${JSON.stringify(segment)}`, 400);
    }
  }
  return segments;
}

// Splits a request path and rejects traversal before any filesystem access.
export function parseRequestPath(rawPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    throw new RegistryError('malformed percent-encoding', 400);
  }
  const segments = decoded.split('/').filter((segment) => segment !== '');
  for (const segment of segments) {
    if (segment === '..' || segment.includes('..')) {
      throw new RegistryError('traversal rejected', 400);
    }
  }
  return segments;
}

export function parsePackagePath(segments) {
  if (segments[0] !== 'packages') throw new RegistryError('not found', 404);
  safeSegments(segments);
  const [, name, version, ...rest] = segments;
  if (!NAME_RE.test(name)) throw new RegistryError(`invalid package name: ${name}`, 400);
  if (!VERSION_RE.test(version)) {
    throw new RegistryError(`invalid version: ${version}; use x.y.z`, 400);
  }
  return { name, version, file: rest.join('/') };
}

function listPackageFiles(directory, relativeDirectory) {
  const entries = readdirSync(directory, { withFileTypes: true });
  entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  const files = [];
  for (const entry of entries) {
    if (isUnsafeSegment(entry.name)) {
      throw new RegistryError(`unsafe path segment: ${JSON.stringify(entry.name)}`, 400);
    }
    const relative = path.posix.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listPackageFiles(path.join(directory, entry.name), relative));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      throw new RegistryError(`unsupported file type: ${relative}`, 400);
    }
  }
  return files;
}

// Serves registry/<name>/<version>/<file> and accepts published files over PUT.
export function createRegistryServer(root, options = {}) {
  const storeRelative = options.store ?? 'registry';
  const storeRoot = path.resolve(root, storeRelative);
  // Digests of published files live in memory for the lifetime of the process.
  const published = new Map();

  const send = (response, status, body, headers = {}) => {
    response.writeHead(status, { 'content-type': 'application/octet-stream', ...headers });
    response.end(body);
  };

  const readBody = (request) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      request.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          reject(new RegistryError('request body too large', 413));
          request.destroy();
          return;
        }
        chunks.push(chunk);
      });
      request.on('end', () => resolve(Buffer.concat(chunks)));
      request.on('error', reject);
    });

  const server = http.createServer(async (request, response) => {
    try {
      const segments = parseRequestPath(request.url.split('?')[0]);
      const { name, version, file } = parsePackagePath(segments);
      const packageDirectory = path.join(storeRoot, name, version);
      if (file === '') {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          send(response, 405, 'method not allowed\n', { allow: 'GET, HEAD' });
          return;
        }
        if (!statSync(packageDirectory, { throwIfNoEntry: false })?.isDirectory()) {
          throw new RegistryError('not found', 404);
        }
        const digests = published.get(`${name}@${version}`);
        const files = listPackageFiles(packageDirectory, '').map((relative) => ({
          path: relative,
          sha256: digests?.get(relative) ?? sha256(readFileSync(path.join(packageDirectory, relative))),
        }));
        send(response, 200, `${JSON.stringify({ name, version, files })}\n`, {
          'content-type': 'application/json',
        });
        return;
      }
      safeSegments(file.split('/'));
      const absolute = path.join(packageDirectory, file);
      const relative = path.relative(storeRoot, absolute);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new RegistryError('unsafe path rejected', 400);
      }
      if (request.method === 'GET' || request.method === 'HEAD') {
        let stat;
        try {
          stat = statSync(absolute);
        } catch {
          throw new RegistryError('not found', 404);
        }
        if (!stat.isFile()) throw new RegistryError('not found', 404);
        const bytes = readFileSync(absolute);
        send(response, 200, request.method === 'HEAD' ? '' : bytes, {
          'content-length': String(stat.size),
          'x-content-sha256': sha256(bytes),
        });
        return;
      }
      if (request.method !== 'PUT') {
        send(response, 405, 'method not allowed\n', { allow: 'GET, HEAD, PUT' });
        return;
      }
      const body = await readBody(request);
      const digest = sha256(body);
      const declared = request.headers['x-content-sha256'];
      if (declared && declared !== digest) {
        throw new RegistryError('integrity mismatch: declared sha256 does not match body', 400);
      }
      mkdirSync(path.dirname(absolute), { recursive: true });
      writeFileSync(absolute, body);
      const key = `${name}@${version}`;
      if (!published.has(key)) published.set(key, new Map());
      published.get(key).set(file, digest);
      send(response, 201, `${JSON.stringify({ path: file, sha256: digest })}\n`, {
        'content-type': 'application/json',
      });
    } catch (error) {
      const status = error instanceof RegistryError ? error.status : 500;
      send(response, status, `${error.message}\n`);
    }
  });
  return server;
}

export function listenLoopback(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

export function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}
