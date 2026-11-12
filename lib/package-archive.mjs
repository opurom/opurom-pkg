// Deterministic stored ZIP archives for signed marketplace packages. Node builtins only.
import { createHash } from 'node:crypto';
import { crc32 } from 'node:zlib';

export const MANIFEST_NAME = 'manifest.json';
export const MAX_ARCHIVE_BYTES = 4 * 1024 * 1024;
export const MAX_FILES = 256;

const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SAFE_PATH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;
const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_RECORD = 0x06054b50;

export class ArchiveError extends Error {}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function assertSafePath(relative) {
  if (
    typeof relative !== 'string' ||
    relative.length === 0 ||
    relative.includes('\0') ||
    relative.includes('\\') ||
    !SAFE_PATH_RE.test(relative) ||
    relative.startsWith('/') ||
    relative.split('/').some((part) => part === '' || part === '.' || part === '..' || part.includes('..'))
  ) {
    throw new ArchiveError(`unsafe archive path: ${JSON.stringify(relative)}`);
  }
  return relative;
}

function validateIdentity(name, version) {
  if (!NAME_RE.test(name)) throw new ArchiveError(`invalid package name: ${String(name)}`);
  if (!VERSION_RE.test(version)) throw new ArchiveError(`invalid package version: ${String(version)}`);
}

function compareNames(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

// Stores entries uncompressed with fixed metadata; callers validate archive paths.
export function encodeZip(entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_FILES) {
    throw new ArchiveError('unsupported archive entry count');
  }
  const prepared = entries
    .map((entry) => {
      if (typeof entry.name !== 'string' || entry.name.length === 0 || entry.name.includes('\0')) {
        throw new ArchiveError('invalid archive entry name');
      }
      const bytes = Buffer.isBuffer(entry.bytes) ? entry.bytes : Buffer.from(entry.bytes);
      return { name: entry.name, nameBytes: Buffer.from(entry.name, 'utf8'), bytes };
    })
    .sort((left, right) => compareNames(left.name, right.name));
  if (new Set(prepared.map((entry) => entry.name)).size !== prepared.length) {
    throw new ArchiveError('duplicate archive entry');
  }

  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of prepared) {
    const size = entry.bytes.length;
    const checksum = crc32(entry.bytes) >>> 0;
    if (entry.nameBytes.length > 0xffff) throw new ArchiveError('archive entry name too long');

    const local = Buffer.alloc(30);
    local.writeUInt32LE(LOCAL_HEADER, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(size, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(entry.nameBytes.length, 26);
    localParts.push(local, entry.nameBytes, entry.bytes);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(CENTRAL_HEADER, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(entry.nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, entry.nameBytes);

    offset += local.length + entry.nameBytes.length + size;
  }

  const central = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_RECORD, 0);
  end.writeUInt16LE(prepared.length, 8);
  end.writeUInt16LE(prepared.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  const archive = Buffer.concat([...localParts, central, end]);
  if (archive.length > MAX_ARCHIVE_BYTES) throw new ArchiveError('archive exceeds bounded size');
  return archive;
}

function readZip(bytes) {
  const archive = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (archive.length < 22 || archive.length > MAX_ARCHIVE_BYTES) {
    throw new ArchiveError('unsupported archive size');
  }
  let endOffset = -1;
  for (let index = archive.length - 22; index >= Math.max(0, archive.length - 65557); index -= 1) {
    if (archive.readUInt32LE(index) === END_RECORD) {
      endOffset = index;
      break;
    }
  }
  if (endOffset < 0 || endOffset + 22 + archive.readUInt16LE(endOffset + 20) !== archive.length) {
    throw new ArchiveError('invalid ZIP end record');
  }
  const count = archive.readUInt16LE(endOffset + 10);
  const centralSize = archive.readUInt32LE(endOffset + 12);
  const centralOffset = archive.readUInt32LE(endOffset + 16);
  // shortcut: ZIP64 is unsupported, upgrade if packages need larger archives.
  if (count === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new ArchiveError('ZIP64 archive rejected');
  }
  if (count === 0 || count > MAX_FILES || centralOffset + centralSize > endOffset) {
    throw new ArchiveError('invalid ZIP central directory');
  }

  const entries = new Map();
  let cursor = centralOffset;
  let extracted = 0;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > centralOffset + centralSize) {
      throw new ArchiveError('truncated ZIP central directory');
    }
    if (archive.readUInt32LE(cursor) !== CENTRAL_HEADER) {
      throw new ArchiveError('invalid ZIP central header');
    }
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const checksum = archive.readUInt32LE(cursor + 16);
    const compressed = archive.readUInt32LE(cursor + 20);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const nameStart = cursor + 46;
    const nameEnd = nameStart + nameLength;
    const next = nameEnd + extraLength + commentLength;
    if (next > centralOffset + centralSize) {
      throw new ArchiveError('truncated ZIP entry metadata');
    }
    const name = archive.subarray(nameStart, nameEnd).toString('utf8');
    assertSafePath(name);
    if (flags !== 0 || method !== 0 || compressed !== size || archive.readUInt16LE(cursor + 34) !== 0) {
      throw new ArchiveError(`unsupported ZIP entry: ${name}`);
    }
    if (entries.has(name)) throw new ArchiveError(`duplicate archive entry: ${name}`);
    if (localOffset + 30 + nameLength > archive.length) {
      throw new ArchiveError(`truncated ZIP local header: ${name}`);
    }
    if (archive.readUInt32LE(localOffset) !== LOCAL_HEADER) {
      throw new ArchiveError(`invalid ZIP local header: ${name}`);
    }
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    if (
      localNameLength !== nameLength ||
      localExtraLength !== 0 ||
      archive.readUInt16LE(localOffset + 6) !== 0 ||
      archive.readUInt16LE(localOffset + 8) !== 0 ||
      archive.readUInt32LE(localOffset + 14) !== checksum ||
      archive.readUInt32LE(localOffset + 18) !== size ||
      archive.readUInt32LE(localOffset + 22) !== size ||
      !archive.subarray(localOffset + 30, localOffset + 30 + nameLength).equals(archive.subarray(nameStart, nameEnd))
    ) {
      throw new ArchiveError(`inconsistent ZIP local header: ${name}`);
    }
    const dataStart = localOffset + 30 + nameLength;
    const dataEnd = dataStart + size;
    if (dataEnd > archive.length || (crc32(archive.subarray(dataStart, dataEnd)) >>> 0) !== checksum) {
      throw new ArchiveError(`ZIP checksum mismatch: ${name}`);
    }
    extracted += size;
    if (extracted > MAX_ARCHIVE_BYTES) throw new ArchiveError('archive exceeds bounded extracted size');
    entries.set(name, Buffer.from(archive.subarray(dataStart, dataEnd)));
    cursor = next;
  }
  if (cursor !== centralOffset + centralSize) {
    throw new ArchiveError('invalid ZIP central directory length');
  }
  return entries;
}

export function createPackageArchive({ name, version, files }) {
  validateIdentity(name, version);
  if (!Array.isArray(files) || files.length === 0 || files.length >= MAX_FILES) {
    throw new ArchiveError('unsupported package file count');
  }
  const prepared = files.map((file) => {
    const relative = assertSafePath(file.path);
    if (relative === MANIFEST_NAME) throw new ArchiveError(`reserved archive path: ${MANIFEST_NAME}`);
    const bytes = Buffer.isBuffer(file.bytes) ? file.bytes : Buffer.from(file.bytes);
    const digest = sha256(bytes);
    if (typeof file.sha256 === 'string' && file.sha256 !== digest) {
      throw new ArchiveError(`local sha256 mismatch: ${relative}`);
    }
    return { path: relative, bytes, sha256: digest };
  });
  prepared.sort((left, right) => compareNames(left.path, right.path));
  if (new Set(prepared.map((file) => file.path)).size !== prepared.length) {
    throw new ArchiveError('duplicate package file');
  }
  const manifest = {
    format: 1,
    name,
    version,
    files: prepared.map((file) => ({ path: file.path, sha256: file.sha256 })),
  };
  return encodeZip([
    { name: MANIFEST_NAME, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8') },
    ...prepared.map((file) => ({ name: file.path, bytes: file.bytes })),
  ]);
}

export function readPackageArchive(bytes, { name, version }) {
  validateIdentity(name, version);
  const entries = readZip(bytes);
  const manifestBytes = entries.get(MANIFEST_NAME);
  if (!manifestBytes) throw new ArchiveError('missing archive manifest');
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    throw new ArchiveError(`invalid archive manifest: ${error.message}`);
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    Array.isArray(manifest) ||
    manifest.format !== 1 ||
    manifest.name !== name ||
    manifest.version !== version ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0 ||
    manifest.files.length >= MAX_FILES
  ) {
    throw new ArchiveError('archive manifest mismatch');
  }
  const files = manifest.files.map((file) => {
    const relative = assertSafePath(file?.path);
    if (relative === MANIFEST_NAME) throw new ArchiveError(`reserved archive path: ${MANIFEST_NAME}`);
    if (typeof file.sha256 !== 'string' || !SHA256_RE.test(file.sha256)) {
      throw new ArchiveError(`invalid archive sha256: ${relative}`);
    }
    const content = entries.get(relative);
    if (!content) throw new ArchiveError(`missing archive file: ${relative}`);
    const digest = sha256(content);
    if (digest !== file.sha256) {
      throw new ArchiveError(`sha256 mismatch: ${relative} (expected ${file.sha256}, got ${digest})`);
    }
    return { path: relative, bytes: content, sha256: digest };
  });
  if (new Set(files.map((file) => file.path)).size !== files.length) {
    throw new ArchiveError('duplicate archive manifest file');
  }
  if (entries.size !== files.length + 1) throw new ArchiveError('unexpected archive entry');
  return { files };
}
