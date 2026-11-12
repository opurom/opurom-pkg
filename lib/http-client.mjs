// Minimal loopback HTTP client for the mock registry. Node builtins only.
import http from 'node:http';
import { MAX_BODY, sha256 } from './registry.mjs';

export class HttpError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// Only loopback HTTP is allowed: this client never reaches the public internet.
function parseRegistryUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new HttpError(`invalid registry URL: ${raw}`, 0);
  }
  if (url.protocol !== 'http:') {
    throw new HttpError(`unsupported registry protocol: ${url.protocol} (http only)`, 0);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    throw new HttpError(`refusing non-loopback registry host: ${host}`, 0);
  }
  return url;
}

export function request(url, { method = 'GET', body = null, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const target = parseRegistryUrl(url.toString());
    const requestBody = body === null ? null : Buffer.from(body);
    const request = http.request(
      {
        host: target.hostname,
        port: target.port || 80,
        path: `${target.pathname}${target.search}`,
        method,
        // No keep-alive: the CLI process must exit right after the response.
        agent: false,
        headers: {
          ...(requestBody === null
            ? {}
            : { 'content-type': 'application/octet-stream', 'content-length': requestBody.length }),
          ...headers,
        },
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY) {
            request.destroy(new HttpError('response body too large', 0));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks),
          });
        });
      },
    );
    request.on('error', (error) =>
      reject(error instanceof HttpError ? error : new HttpError(error.message, 0)),
    );
    if (requestBody !== null) request.write(requestBody);
    request.end();
  });
}

export function expectOk(response, label) {
  if (response.status !== 200) {
    throw new HttpError(
      `${label} failed with status ${response.status}: ${response.body.toString('utf8').trim()}`,
      response.status,
    );
  }
  return response;
}

// Integrity check: the transferred bytes must match the advertised digest.
export function assertIntegrity(response, expectedSha256, label) {
  const advertised = response.headers['x-content-sha256'];
  const actual = sha256(response.body);
  if (advertised && advertised !== actual) {
    throw new HttpError(`${label}: server digest mismatch`, 0);
  }
  if (expectedSha256 && expectedSha256 !== actual) {
    throw new HttpError(`${label}: sha256 mismatch (expected ${expectedSha256}, got ${actual})`, 0);
  }
  return actual;
}
