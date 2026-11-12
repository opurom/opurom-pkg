// GitHub Release registry and its loopback HTTP mock. Node builtins only.
import http from 'node:http';
import { MAX_ARCHIVE_BYTES, sha256 } from './package-archive.mjs';

export const MAX_SIGNATURE_BYTES = 4096;
export const MAX_ASSET_BYTES = MAX_ARCHIVE_BYTES;
const MAX_JSON_BYTES = 1024 * 1024;
const ASSET_PREFIX = 'opurom-pkg-';
const TAG_RE = /^opurom-pkg-([a-z0-9][a-z0-9._-]*)-(\d+\.\d+\.\d+)$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$/;
const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})?$/;

export class GitHubRegistryError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.status = status;
  }
}

export class RegistryNetworkError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

class MockError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function validateNameVersion(name, version) {
  if (!NAME_RE.test(name)) throw new GitHubRegistryError(`invalid package name: ${String(name)}`);
  if (!VERSION_RE.test(version)) {
    throw new GitHubRegistryError(`invalid package version: ${String(version)}; use x.y.z`);
  }
}

export function parseRepository(spec) {
  if (typeof spec !== 'string') throw new GitHubRegistryError('invalid GitHub repository');
  const parts = spec.split('/');
  const [owner, repo] = parts;
  if (
    parts.length !== 2 ||
    !OWNER_RE.test(owner) ||
    !REPO_RE.test(repo) ||
    repo.includes('..')
  ) {
    throw new GitHubRegistryError(`invalid GitHub repository: ${spec}; use owner/repo`);
  }
  return { owner, repo, path: `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` };
}

export function assetNames(name, version) {
  validateNameVersion(name, version);
  const tag = `${ASSET_PREFIX}${name}-${version}`;
  const archive = `${tag}.zip`;
  return { tag, archive, signature: `${archive}.sig` };
}

export function parseTag(tag) {
  if (typeof tag !== 'string') return null;
  const match = TAG_RE.exec(tag);
  if (!match) return null;
  return { tag, name: match[1], version: match[2], ...assetNames(match[1], match[2]) };
}

export function parseAssetName(name) {
  if (typeof name !== 'string' || !name.endsWith('.zip')) return null;
  const parsed = parseTag(name.slice(0, -4));
  return parsed && parsed.archive === name ? parsed : null;
}

export function parseSignatureName(name) {
  if (typeof name !== 'string' || !name.endsWith('.sig')) return null;
  return parseAssetName(name.slice(0, -4));
}

export function parseReleaseDigest(body) {
  if (typeof body !== 'string') return null;
  const match = /^sha256:[ \t]*([0-9a-f]{64})[ \t]*$/m.exec(body);
  return match ? match[1] : null;
}

export function releaseBody(name, version, archive, digest) {
  return `OPUROM signed package ${name}@${version}\nasset: ${archive}\nsha256: ${digest}`;
}

function redact(text, token) {
  let value = String(text);
  if (token) value = value.split(token).join('[REDACTED]');
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 400);
}

function displayUrl(value, token) {
  const text = redact(value, token);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new GitHubRegistryError('registry returned an invalid release URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new GitHubRegistryError('registry returned an unsupported release URL');
  }
  return url.toString();
}

function loopbackHost(hostname) {
  return ['127.0.0.1', 'localhost', '::1'].includes(hostname.replace(/^\[|\]$/g, ''));
}

function resolveEndpoints() {
  const raw = process.env.OPUROM_GITHUB_API_URL;
  if (!raw) {
    return {
      api: new URL('https://api.github.com'),
      upload: new URL('https://uploads.github.com'),
      mock: false,
    };
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new GitHubRegistryError('OPUROM_GITHUB_API_URL is not a valid URL');
  }
  const plainOrigin = url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password;
  if (plainOrigin && url.protocol === 'https:' && url.hostname === 'api.github.com') {
    return { api: url, upload: new URL('https://uploads.github.com'), mock: false };
  }
  if (plainOrigin && url.protocol === 'http:' && loopbackHost(url.hostname)) {
    return { api: url, upload: url, mock: true };
  }
  throw new GitHubRegistryError(
    'OPUROM_GITHUB_API_URL must be https://api.github.com or a loopback HTTP origin',
  );
}

function assertId(value, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new GitHubRegistryError(`registry returned an invalid ${label} id`);
  }
  return String(value);
}

function assertAssetSize(asset, maximum, label) {
  if (
    typeof asset?.size !== 'number' ||
    !Number.isSafeInteger(asset.size) ||
    asset.size < 0 ||
    asset.size > maximum
  ) {
    throw new GitHubRegistryError(`${label} exceeds bounded size or has an invalid size`);
  }
}

export function createGithubRegistry({ token = null } = {}) {
  const endpoints = resolveEndpoints();
  const authorization = token ? { authorization: `Bearer ${token}` } : {};
  const headers = (extra = {}) => ({
    'user-agent': 'opurom-pkg-r9',
    accept: 'application/vnd.github+json',
    ...authorization,
    ...extra,
  });

  function networkReason(error) {
    if (error?.name === 'TimeoutError') return 'request timed out';
    const cause = error?.cause;
    const detail = cause?.code
      ? `${cause.code}: ${cause.message || 'fetch failed'}`
      : cause?.message || error?.message || 'fetch failed';
    return redact(detail, token) || 'fetch failed';
  }

  async function call(url, options, label) {
    let response;
    try {
      response = await fetch(url, {
        ...options,
        headers: headers(options.headers),
        signal: AbortSignal.timeout(15000),
        redirect: 'follow',
      });
    } catch (error) {
      throw new RegistryNetworkError(`${label}: ${networkReason(error)}`);
    }
    return response;
  }

  function assertApiOrigin(response, label) {
    const final = new URL(response.url);
    const allowed = endpoints.mock
      ? [endpoints.api.origin]
      : [endpoints.api.origin, endpoints.upload.origin];
    if (!allowed.includes(final.origin)) {
      throw new GitHubRegistryError(`${label}: unexpected API response origin ${final.origin}`);
    }
  }

  function assertDownloadOrigin(response, label) {
    const final = new URL(response.url);
    if (endpoints.mock) {
      if (final.protocol !== 'http:' || final.origin !== endpoints.api.origin) {
        throw new GitHubRegistryError(`${label}: unexpected mock download origin ${final.origin}`);
      }
      return;
    }
    const host = final.hostname;
    const allowed =
      host === 'github.com' ||
      host === 'api.github.com' ||
      host.endsWith('.github.com') ||
      host.endsWith('.githubusercontent.com');
    if (final.protocol !== 'https:' || !allowed) {
      throw new GitHubRegistryError(`${label}: asset download is not HTTPS on a GitHub host`);
    }
  }

  async function readBounded(response, maximum, label, kind = 'api') {
    if (kind === 'download') assertDownloadOrigin(response, label);
    else assertApiOrigin(response, label);
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maximum) {
      throw new GitHubRegistryError(`${label}: response exceeds ${maximum} bytes`);
    }
    if (!response.body) return Buffer.alloc(0);
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maximum) {
        await reader.cancel();
        throw new GitHubRegistryError(`${label}: response exceeds ${maximum} bytes`);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  }

  async function httpError(response, label, kind = 'api') {
    const bytes = await readBounded(response, 4096, label, kind).catch(() => Buffer.alloc(0));
    let message = bytes.toString('utf8').trim();
    try {
      const parsed = JSON.parse(message);
      if (parsed?.message) message = parsed.message;
    } catch {
      // Keep the plain response body when GitHub does not return JSON.
    }
    throw new GitHubRegistryError(
      `${label} failed with HTTP ${response.status}: ${redact(message || 'no response body', token)}`,
      response.status,
    );
  }

  async function readJson(response, label) {
    if (!response.ok) await httpError(response, label);
    const bytes = await readBounded(response, MAX_JSON_BYTES, label);
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new GitHubRegistryError(`${label}: invalid JSON response`);
    }
  }

  async function apiRequest(path, { method = 'GET', body = null, label, contentType } = {}) {
    const url = new URL(path, endpoints.api);
    const response = await call(
      url,
      {
        method,
        headers: contentType ? { 'content-type': contentType } : {},
        ...(body === null ? {} : { body }),
      },
      label,
    );
    return readJson(response, label);
  }

  async function getRelease(repo, tag, label) {
    const url = new URL(`/${repo.path}/releases/tags/${encodeURIComponent(tag)}`, endpoints.api);
    const response = await call(url, { method: 'GET' }, label);
    if (response.status === 404) {
      await readBounded(response, 4096, label);
      return null;
    }
    return readJson(response, label);
  }

  async function deleteAsset(repo, id, label) {
    const assetId = assertId(id, 'asset');
    const url = new URL(`/${repo.path}/releases/assets/${assetId}`, endpoints.api);
    const response = await call(url, { method: 'DELETE' }, label);
    if (!response.ok) await httpError(response, label);
    await readBounded(response, 4096, label);
  }

  async function uploadAsset(repo, releaseId, name, bytes, label) {
    const id = assertId(releaseId, 'release');
    const url = new URL(
      `/${repo.path}/releases/${id}/assets?name=${encodeURIComponent(name)}`,
      endpoints.upload,
    );
    const response = await call(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: bytes,
      },
      label,
    );
    const asset = await readJson(response, label);
    if (asset?.name !== name) throw new GitHubRegistryError(`${label}: unexpected asset name`);
    return asset;
  }

  async function downloadAsset(repo, asset, maximum, label) {
    const id = assertId(asset.id, 'asset');
    const url = new URL(`/${repo.path}/releases/assets/${id}`, endpoints.api);
    const response = await call(
      url,
      { method: 'GET', headers: { accept: 'application/octet-stream' } },
      label,
    );
    if (!response.ok) await httpError(response, label, 'download');
    return readBounded(response, maximum, label, 'download');
  }

  async function publish({ repository, name, version, archive, signature, digest }) {
    const repo = parseRepository(repository);
    const names = assetNames(name, version);
    if (!Buffer.isBuffer(archive) || archive.length > MAX_ARCHIVE_BYTES) {
      throw new GitHubRegistryError('archive exceeds bounded size');
    }
    if (!Buffer.isBuffer(signature) || signature.length > MAX_SIGNATURE_BYTES) {
      throw new GitHubRegistryError('signature exceeds bounded size');
    }
    const actualDigest = sha256(archive);
    if (typeof digest !== 'string' || !SHA256_RE.test(digest) || digest !== actualDigest) {
      throw new GitHubRegistryError('archive sha256 does not match release metadata');
    }
    const body = releaseBody(name, version, names.archive, digest);
    let release = await getRelease(repo, names.tag, 'get GitHub Release');
    if (release) {
      const id = assertId(release.id, 'release');
      release = await apiRequest(`/${repo.path}/releases/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ name: `OPUROM ${name}@${version}`, body }),
        contentType: 'application/json',
        label: 'patch GitHub Release',
      });
    } else {
      release = await apiRequest(`/${repo.path}/releases`, {
        method: 'POST',
        body: JSON.stringify({
          tag_name: names.tag,
          name: `OPUROM ${name}@${version}`,
          body,
          draft: false,
          prerelease: false,
        }),
        contentType: 'application/json',
        label: 'create GitHub Release',
      });
    }
    for (const asset of Array.isArray(release.assets) ? release.assets : []) {
      if (asset?.name === names.archive || asset?.name === names.signature) {
        await deleteAsset(repo, asset.id, `replace asset ${asset.name}`);
      }
    }
    const archiveAsset = await uploadAsset(
      repo,
      release.id,
      names.archive,
      archive,
      `upload ${names.archive}`,
    );
    const signatureAsset = await uploadAsset(
      repo,
      release.id,
      names.signature,
      signature,
      `upload ${names.signature}`,
    );
    return {
      tag: names.tag,
      releaseUrl: displayUrl(release.html_url, token),
      asset: archiveAsset.name,
      signature: signatureAsset.name,
      digest,
    };
  }

  async function search({ repository, name = null }) {
    const repo = parseRepository(repository);
    if (name !== null) validateNameVersion(name, '0.0.0');
    const releases = await apiRequest(
      `/${repo.path}/releases?per_page=100`,
      { label: 'list GitHub Releases' },
    );
    if (!Array.isArray(releases)) throw new GitHubRegistryError('registry returned an invalid release list');
    const rows = new Map();
    for (const release of releases) {
      const assets = Array.isArray(release?.assets) ? release.assets : [];
      if (release?.draft === true || !parseReleaseDigest(release.body)) continue;
      for (const asset of assets) {
        const parsed = parseAssetName(asset?.name);
        if (!parsed || (name !== null && parsed.name !== name)) continue;
        if (!assets.some((candidate) => candidate?.name === parsed.signature)) continue;
        rows.set(`${parsed.name}@${parsed.version}`, {
          name: parsed.name,
          version: parsed.version,
          tag: release.tag_name,
          releaseUrl: displayUrl(release.html_url, token),
          asset: parsed.archive,
          signature: parsed.signature,
          digest: parseReleaseDigest(release.body),
        });
      }
    }
    return [...rows.values()].sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : left.version.localeCompare(right.version),
    );
  }

  async function download({ repository, name, version }) {
    const repo = parseRepository(repository);
    const names = assetNames(name, version);
    const release = await getRelease(repo, names.tag, 'get GitHub Release');
    if (!release) throw new GitHubRegistryError(`missing release for tag ${names.tag}`, 404);
    const assets = Array.isArray(release.assets) ? release.assets : [];
    const archiveAsset = assets.find((asset) => asset?.name === names.archive);
    const signatureAsset = assets.find((asset) => asset?.name === names.signature);
    if (!signatureAsset) throw new GitHubRegistryError(`missing signature asset: ${names.signature}`);
    if (!archiveAsset) throw new GitHubRegistryError(`missing archive asset: ${names.archive}`);
    assertAssetSize(archiveAsset, MAX_ARCHIVE_BYTES, names.archive);
    assertAssetSize(signatureAsset, MAX_SIGNATURE_BYTES, names.signature);
    const digest = parseReleaseDigest(release.body);
    if (!digest) throw new GitHubRegistryError('missing sha256 in release body');
    const archive = await downloadAsset(repo, archiveAsset, MAX_ARCHIVE_BYTES, names.archive);
    const signature = await downloadAsset(repo, signatureAsset, MAX_SIGNATURE_BYTES, names.signature);
    return {
      archive,
      signature,
      digest,
      releaseUrl: displayUrl(release.html_url, token),
      asset: names.archive,
      signatureAsset: names.signature,
      tag: names.tag,
    };
  }

  return { publish, search, download };
}

function send(response, status, body, contentType = 'application/octet-stream') {
  response.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length) });
  response.end(body);
}

function sendJson(response, status, value) {
  send(response, status, Buffer.from(`${JSON.stringify(value)}\n`, 'utf8'), 'application/json');
}

function requestSegments(request) {
  const raw = request.url.split('?')[0];
  if (/%2f/i.test(raw)) throw new MockError('encoded slash rejected');
  let decoded;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    throw new MockError('malformed percent-encoding');
  }
  if (decoded.includes('..') || decoded.includes('\\') || decoded.includes('\0')) {
    throw new MockError('traversal rejected');
  }
  return decoded.split('/').filter(Boolean);
}

function readBody(request, maximum) {
  return new Promise((resolve, reject) => {
    const declared = Number(request.headers['content-length']);
    const chunks = [];
    let size = 0;
    let tooLarge = Number.isFinite(declared) && declared > maximum;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > maximum) {
        tooLarge = true;
        chunks.length = 0;
      } else if (!tooLarge) {
        chunks.push(chunk);
      }
    });
    request.on('end', () => {
      if (tooLarge) reject(new MockError('asset exceeds bounded size', 413));
      else resolve(Buffer.concat(chunks));
    });
    request.on('error', reject);
  });
}

// In-memory GitHub REST subset for offline CI; it never writes files or logs credentials.
export function createGithubMockServer() {
  const releases = new Map();
  const assets = new Map();
  let nextId = 1;

  function assetView(asset, request) {
    const origin = `http://${request.headers.host || '127.0.0.1'}`;
    const repo = parseRepository(`${asset.owner}/${asset.repo}`);
    return {
      id: asset.id,
      name: asset.name,
      size: asset.bytes.length,
      content_type: 'application/octet-stream',
      browser_download_url: `${origin}/${repo.path}/releases/assets/${asset.id}`,
      url: `${origin}/${repo.path}/releases/assets/${asset.id}`,
    };
  }

  function releaseView(release, request) {
    const origin = `http://${request.headers.host || '127.0.0.1'}`;
    const repo = parseRepository(`${release.owner}/${release.repo}`);
    return {
      id: release.id,
      tag_name: release.tag,
      name: release.name,
      body: release.body,
      draft: false,
      prerelease: false,
      html_url: `https://github.com/${release.owner}/${release.repo}/releases/tag/${release.tag}`,
      upload_url: `${origin}/${repo.path}/releases/${release.id}/assets{?name,label}`,
      assets: release.assetIds
        .map((id) => assets.get(id))
        .filter(Boolean)
        .map((asset) => assetView(asset, request)),
    };
  }

  function findReleaseById(owner, repo, rawId) {
    const id = Number(rawId);
    for (const release of releases.values()) {
      if (release.id === id && release.owner === owner && release.repo === repo) return release;
    }
    throw new MockError('not found', 404);
  }

  const server = http.createServer(async (request, response) => {
    try {
      const segments = requestSegments(request);
      if (segments[0] !== 'repos' || segments.length < 4 || segments[3] !== 'releases') {
        throw new MockError('not found', 404);
      }
      const repo = parseRepository(`${segments[1]}/${segments[2]}`);
      const key = `${repo.owner}/${repo.repo}`;
      const rest = segments.slice(4);
      const url = new URL(request.url, 'http://127.0.0.1');

      if (rest.length === 0 && request.method === 'GET') {
        const listed = [...releases.values()]
          .filter((release) => `${release.owner}/${release.repo}` === key)
          .map((release) => releaseView(release, request));
        sendJson(response, 200, listed);
        return;
      }
      if (rest.length === 0 && request.method === 'POST') {
        const payload = JSON.parse((await readBody(request, 64 * 1024)).toString('utf8'));
        const parsed = parseTag(payload?.tag_name);
        if (!parsed || typeof payload?.body !== 'string') {
          throw new MockError('invalid release tag or body');
        }
        const releaseKey = `${key}:${parsed.tag}`;
        if (releases.has(releaseKey)) throw new MockError('release already exists', 422);
        const release = {
          id: nextId++,
          owner: repo.owner,
          repo: repo.repo,
          tag: parsed.tag,
          name: String(payload.name || parsed.tag),
          body: payload.body,
          assetIds: [],
        };
        releases.set(releaseKey, release);
        sendJson(response, 201, releaseView(release, request));
        return;
      }
      if (rest.length === 2 && rest[0] === 'tags' && request.method === 'GET') {
        const release = releases.get(`${key}:${rest[1]}`);
        if (!release) throw new MockError('not found', 404);
        sendJson(response, 200, releaseView(release, request));
        return;
      }
      if (rest.length === 1 && request.method === 'PATCH') {
        const release = findReleaseById(repo.owner, repo.repo, rest[0]);
        const payload = JSON.parse((await readBody(request, 64 * 1024)).toString('utf8'));
        if (typeof payload?.body === 'string') release.body = payload.body;
        if (typeof payload?.name === 'string') release.name = payload.name;
        sendJson(response, 200, releaseView(release, request));
        return;
      }
      if (rest.length === 2 && rest[1] === 'assets' && request.method === 'POST') {
        const release = findReleaseById(repo.owner, repo.repo, rest[0]);
        const name = url.searchParams.get('name');
        const parsed = parseAssetName(name) || parseSignatureName(name);
        if (!parsed || parsed.tag !== release.tag) throw new MockError('invalid asset name');
        if (release.assetIds.some((id) => assets.get(id)?.name === name)) {
          throw new MockError('asset already exists', 422);
        }
        const maximum = name.endsWith('.sig') ? MAX_SIGNATURE_BYTES : MAX_ARCHIVE_BYTES;
        const bytes = await readBody(request, maximum);
        const asset = {
          id: nextId++,
          owner: repo.owner,
          repo: repo.repo,
          name,
          bytes,
        };
        assets.set(asset.id, asset);
        release.assetIds.push(asset.id);
        sendJson(response, 201, assetView(asset, request));
        return;
      }
      if (rest.length === 2 && rest[0] === 'assets') {
        const id = Number(rest[1]);
        const asset = assets.get(id);
        if (!asset || asset.owner !== repo.owner || asset.repo !== repo.repo) {
          throw new MockError('not found', 404);
        }
        if (request.method === 'DELETE') {
          assets.delete(id);
          for (const release of releases.values()) {
            release.assetIds = release.assetIds.filter((assetId) => assetId !== id);
          }
          response.writeHead(204);
          response.end();
          return;
        }
        if (request.method === 'GET') {
          if ((request.headers.accept || '').includes('application/octet-stream')) {
            send(response, 200, asset.bytes);
          } else {
            sendJson(response, 200, assetView(asset, request));
          }
          return;
        }
      }
      throw new MockError('not found', 404);
    } catch (error) {
      const status = error instanceof MockError ? error.status : 400;
      sendJson(response, status, { message: error.message });
    }
  });
  return server;
}
