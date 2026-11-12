#!/usr/bin/env node
// OPUROM offline package CLI: init | add | remove | list | verify | lock |
// sign | registry-server | publish | install. Node builtins only.
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  SIG_EXT,
  SigningError,
  loadOrCreateKeypair,
  readPublicKey,
  readSignature,
  signBytes,
  verifyBytes,
  writeSignature,
} from '../lib/signing.mjs';
import {
  closeServer,
  createRegistryServer,
  listenLoopback,
} from '../lib/registry.mjs';
import { HttpError, assertIntegrity, expectOk, request } from '../lib/http-client.mjs';

// The project root is the current directory, or the package directory that owns
// this script when the CLI is invoked from outside the project.
function resolveRoot() {
  const current = realpathSync(process.cwd());
  if (existsSync(path.join(current, 'opurom.json'))) return current;
  const packaged = path.resolve(import.meta.dirname, '..');
  // A fresh project directory must stay usable for init.
  if (existsSync(path.join(current, 'registry'))) return current;
  if (existsSync(path.join(packaged, 'opurom.json'))) return packaged;
  return current;
}

const ROOT = resolveRoot();
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const READ_FLAGS = constants.O_RDONLY | NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | NOFOLLOW;
const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
// shortcut: exact x.y.z versions only, upgrade when ranges or prerelease tags are needed.
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
// Local mock registry only: loopback HTTP, no TLS, no remote hosts.
const DEFAULT_REGISTRY_URL = 'http://127.0.0.1:4873';

const USAGE = `usage: opurom-pkg <command>

  init <name>             write opurom.json and an empty opurom.lock
  add <name>@<version>    resolve from registry/ and refresh opurom.lock
  remove <name>           remove a dependency and refresh opurom.lock
  list                    show packages in opurom.lock
  verify [--signed]       recompute SHA-256 of every locked file
  lock                    regenerate deterministic opurom.lock
  sign                    write detached Ed25519 signatures
  registry-server [--port N]  serve registry/ on loopback HTTP
  publish <name>@<version>    publish a local package over loopback HTTP
  install <name>@<version>    install an exact package over loopback HTTP

Run from the project root. Only exact x.y.z versions and loopback HTTP are
supported. OPUROM_REGISTRY_URL overrides http://127.0.0.1:4873.`;

class CliError extends Error {
  constructor(message, code = 1) {
    super(message);
    this.code = code;
  }
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function comparePackages(left, right) {
  return compareStrings(left.name, right.name) || compareStrings(left.version, right.version);
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameList(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function packageDigest(files) {
  return sha256(JSON.stringify(files));
}

function registryPath(name, version) {
  return `registry/${name}/${version}`;
}

function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

function assertInside(absolute, relative, label) {
  const difference = path.relative(ROOT, absolute);
  if (
    difference === '' ||
    difference.split(path.sep).includes('..') ||
    path.isAbsolute(difference)
  ) {
    throw new CliError(
      `unsafe ${label}: ${JSON.stringify(relative)} (absolute or .. traversal rejected)`,
    );
  }
}

function assertRelative(relative, label) {
  if (typeof relative !== 'string' || relative.length === 0) {
    throw new CliError(`${label} must be a non-empty relative path`);
  }
  if (
    relative.includes('\0') ||
    relative.includes('\\') ||
    path.isAbsolute(relative) ||
    path.win32.isAbsolute(relative)
  ) {
    throw new CliError(
      `unsafe ${label}: ${JSON.stringify(relative)} (absolute or .. traversal rejected)`,
    );
  }
  const parts = relative.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    throw new CliError(
      `unsafe ${label}: ${JSON.stringify(relative)} (absolute or .. traversal rejected)`,
    );
  }
  return parts;
}

function resolveContained(relative, label, kind) {
  const parts = assertRelative(relative, label);
  const absolute = path.resolve(ROOT, ...parts);
  assertInside(absolute, relative, label);
  let current = ROOT;
  let stat;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    try {
      stat = lstatSync(current);
    } catch (error) {
      if (error.code === 'ENOENT') throw new CliError(`missing ${label}: ${relative}`);
      throw new CliError(`cannot stat ${label}: ${error.message}`);
    }
    if (stat.isSymbolicLink()) {
      throw new CliError(`unsafe ${label}: ${relative} (symlink rejected)`);
    }
    if (index < parts.length - 1 && !stat.isDirectory()) {
      throw new CliError(`not a directory: ${relative}`);
    }
  }
  if (kind === 'file' && !stat.isFile()) throw new CliError(`not a file: ${relative}`);
  if (kind === 'directory' && !stat.isDirectory()) {
    throw new CliError(`not a directory: ${relative}`);
  }
  return { absolute: current, relative };
}

function readNoFollow(absolute, label, encoding) {
  let fd;
  try {
    fd = openSync(absolute, READ_FLAGS);
  } catch (error) {
    if (error.code === 'ELOOP') throw new CliError(`unsafe ${label}: symlink rejected`);
    throw new CliError(`cannot read ${label}: ${error.message}`);
  }
  try {
    return encoding === undefined ? readFileSync(fd) : readFileSync(fd, encoding);
  } catch (error) {
    throw new CliError(`cannot read ${label}: ${error.message}`);
  } finally {
    closeSync(fd);
  }
}

function hashFile(absolute, label) {
  return sha256(readNoFollow(absolute, label));
}

function readJsonAt(relative, label) {
  const target = resolveContained(relative, label, 'file');
  const text = readNoFollow(target.absolute, label, 'utf8');
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new CliError(`invalid JSON in ${label}: ${error.message}`);
  }
}

function preparedWrite(relative) {
  assertRelative(relative, `write target ${relative}`);
  const absolute = path.resolve(ROOT, relative);
  assertInside(absolute, relative, `write target ${relative}`);
  try {
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      throw new CliError(`unsafe write target: ${relative} (symlink rejected)`);
    }
    if (!stat.isFile()) throw new CliError(`not a file: ${relative}`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    if (error.code !== 'ENOENT') {
      throw new CliError(`cannot stat ${relative}: ${error.message}`);
    }
  }
  return absolute;
}

function writeTextFile(relative, text) {
  const target = preparedWrite(relative);
  const temporaryRelative = `${relative}.tmp`;
  const temporary = preparedWrite(temporaryRelative);
  try {
    const fd = openSync(temporary, WRITE_FLAGS, 0o600);
    try {
      writeFileSync(fd, text, 'utf8');
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, target);
  } catch (error) {
    try {
      rmSync(temporary, { force: true });
    } catch {
      // The original write error is more useful than a cleanup error.
    }
    throw new CliError(`cannot write ${relative}: ${error.message}`);
  }
}

function writeJsonFile(relative, value) {
  writeTextFile(relative, stableJson(value));
}

function validateName(name, label) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    throw new CliError(`invalid ${label}: ${String(name)}`);
  }
}

function validateVersion(version, label) {
  if (typeof version !== 'string' || !VERSION_RE.test(version)) {
    throw new CliError(`invalid version for ${label}: ${String(version)}; use x.y.z`);
  }
}

function validateManifest(data) {
  if (!plainObject(data)) throw new CliError('manifest must be a JSON object');
  validateName(data.name, 'project name');
  validateVersion(data.version, 'project version');
  if (!Array.isArray(data.moduleRoots)) {
    throw new CliError('moduleRoots must be an array');
  }
  for (const moduleRoot of data.moduleRoots) {
    assertRelative(moduleRoot, 'moduleRoot');
  }
  if (!plainObject(data.dependencies)) {
    throw new CliError('dependencies must be an object');
  }
  const dependencies = Object.entries(data.dependencies).map(([name, version]) => {
    validateName(name, 'dependency name');
    validateVersion(version, `dependency ${name}`);
    return [name, version];
  });
  dependencies.sort((left, right) => compareStrings(left[0], right[0]));
  return { data, dependencies };
}

function readManifestFile() {
  if (!existsSync(path.join(ROOT, 'opurom.json'))) {
    throw new CliError('missing opurom.json; run init first');
  }
  return validateManifest(readJsonAt('opurom.json', 'manifest'));
}

function validateLockedFile(file, pkg, index) {
  if (!plainObject(file)) throw new CliError(`invalid file #${index} for ${pkg.name}`);
  assertRelative(file.path, `file path for ${pkg.name}`);
  if (!file.path.startsWith(`${pkg.path}/`)) {
    throw new CliError(`file ${file.path} is outside package ${pkg.path}`);
  }
  if (typeof file.sha256 !== 'string' || !SHA256_RE.test(file.sha256)) {
    throw new CliError(`invalid sha256 for ${file.path}`);
  }
  return { path: file.path, sha256: file.sha256 };
}

function validateLockedPackage(pkg, index) {
  const label = `package #${index}`;
  if (!plainObject(pkg)) throw new CliError(`${label} must be an object`);
  validateName(pkg.name, `${label} name`);
  validateVersion(pkg.version, `${label} ${pkg.name}`);
  assertRelative(pkg.path, `${label} path`);
  const expectedPath = registryPath(pkg.name, pkg.version);
  if (pkg.path !== expectedPath) {
    throw new CliError(`unexpected ${label} path: ${pkg.path}; expected ${expectedPath}`);
  }
  if (typeof pkg.sha256 !== 'string' || !SHA256_RE.test(pkg.sha256)) {
    throw new CliError(`invalid sha256 for ${pkg.name}@${pkg.version}`);
  }
  if (!Array.isArray(pkg.files) || pkg.files.length === 0) {
    throw new CliError(`no locked files for ${pkg.name}@${pkg.version}`);
  }
  const files = pkg.files.map((file, fileIndex) => validateLockedFile(file, pkg, fileIndex));
  const sortedFiles = [...files].sort((left, right) => compareStrings(left.path, right.path));
  if (!files.every((file, fileIndex) => file === sortedFiles[fileIndex])) {
    throw new CliError(`opurom.lock files are not sorted for ${pkg.name}`);
  }
  if (new Set(files.map((file) => file.path)).size !== files.length) {
    throw new CliError(`duplicate locked file for ${pkg.name}`);
  }
  return {
    name: pkg.name,
    version: pkg.version,
    path: pkg.path,
    sha256: pkg.sha256,
    files,
  };
}

function validateLock(data) {
  if (!plainObject(data)) throw new CliError('lockfile must be a JSON object');
  if (data.version !== 1) throw new CliError('unsupported opurom.lock version');
  if (!Array.isArray(data.packages)) throw new CliError('packages must be an array');
  const packages = data.packages.map(validateLockedPackage);
  const sorted = [...packages].sort(comparePackages);
  if (!packages.every((pkg, index) => pkg === sorted[index])) {
    throw new CliError('opurom.lock packages are not sorted');
  }
  if (new Set(packages.map((pkg) => pkg.name)).size !== packages.length) {
    throw new CliError('duplicate locked package name');
  }
  return packages;
}

function readLockFile() {
  if (!existsSync(path.join(ROOT, 'opurom.lock'))) {
    throw new CliError('missing opurom.lock; run lock first');
  }
  return validateLock(readJsonAt('opurom.lock', 'lockfile'));
}

function walkFiles(relativeDirectory, absoluteDirectory) {
  const entries = readdirSync(absoluteDirectory, { withFileTypes: true });
  entries.sort((left, right) => compareStrings(left.name, right.name));
  const files = [];
  for (const entry of entries) {
    // Detached signatures sit next to files but are not package content.
    if (entry.name.endsWith(SIG_EXT)) continue;
    assertRelative(entry.name, 'filesystem name');
    const relative = path.posix.join(relativeDirectory, entry.name);
    assertRelative(relative, 'registry path');
    if (entry.isSymbolicLink()) {
      throw new CliError(`unsafe registry path: ${relative} (symlink rejected)`);
    }
    const absolute = path.join(absoluteDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(relative, absolute));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      throw new CliError(`unsupported file type: ${relative}`);
    }
  }
  return files;
}

function collectPackage(name, version) {
  validateName(name, 'package name');
  validateVersion(version, `package ${name}`);
  const packageRelative = registryPath(name, version);
  if (!existsSync(path.resolve(ROOT, packageRelative))) {
    throw new CliError(
      `unknown local package: ${name}@${version} (expected ${packageRelative})`,
    );
  }
  const directory = resolveContained(
    packageRelative,
    `registry package ${name}@${version}`,
    'directory',
  );
  const metadataRelative = path.posix.join(packageRelative, 'opurom-pkg.json');
  const metadata = readJsonAt(metadataRelative, `registry manifest for ${name}@${version}`);
  if (!plainObject(metadata) || metadata.name !== name || metadata.version !== version) {
    throw new CliError(`registry manifest mismatch: ${metadataRelative}`);
  }
  if (
    !Array.isArray(metadata.files) ||
    metadata.files.length === 0 ||
    metadata.files.some((file) => typeof file !== 'string')
  ) {
    throw new CliError(`registry manifest needs a files array: ${metadataRelative}`);
  }
  const declared = metadata.files.map((file) => {
    assertRelative(file, `registry file for ${name}@${version}`);
    return path.posix.join(packageRelative, file);
  });
  declared.sort(compareStrings);
  if (new Set(declared).size !== declared.length) {
    throw new CliError(`duplicate registry file for ${name}@${version}`);
  }
  const actual = walkFiles(packageRelative, directory.absolute).sort(compareStrings);
  if (!sameList(declared, actual)) {
    throw new CliError(`registry file list mismatch for ${name}@${version}`);
  }
  const files = declared.map((relative) => {
    const target = resolveContained(relative, `registry file ${relative}`, 'file');
    return { path: relative, sha256: hashFile(target.absolute, relative) };
  });
  return {
    name,
    version,
    path: packageRelative,
    sha256: packageDigest(files),
    files,
  };
}

function buildPackages(dependencies) {
  return dependencies.map(([name, version]) => collectPackage(name, version));
}

// shortcut: two atomic replacements are not one transaction; verify detects drift, upgrade for concurrent writers.
function writeProjectState(manifestData, dependencies, packages) {
  const nextManifest = {
    ...manifestData,
    dependencies: Object.fromEntries(dependencies),
  };
  writeJsonFile('opurom.json', nextManifest);
  writeJsonFile('opurom.lock', { version: 1, packages });
}

function parseSpec(spec, command = 'add') {
  const at = spec.lastIndexOf('@');
  if (at <= 0 || at === spec.length - 1) {
    throw new CliError(`${command} needs <name>@<version>, for example opurom-ui@0.1.0`);
  }
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  validateName(name, 'package name');
  validateVersion(version, `package ${name}`);
  return { name, version };
}

function commandInit(name) {
  validateName(name, 'project name');
  const manifestTarget = preparedWrite('opurom.json');
  const lockTarget = preparedWrite('opurom.lock');
  if (existsSync(manifestTarget) || existsSync(lockTarget)) {
    throw new CliError('opurom.json or opurom.lock already exists; init will not overwrite');
  }
  writeJsonFile('opurom.json', {
    name,
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {},
  });
  writeJsonFile('opurom.lock', { version: 1, packages: [] });
  process.stdout.write(`initialized ${name}\n`);
}

// Updates opurom.json and opurom.lock after a dependency became available locally.
function applyDependency(name, version) {
  const { data, dependencies } = readManifestFile();
  const byName = new Map(dependencies);
  byName.set(name, version);
  const nextDependencies = [...byName].sort((left, right) =>
    compareStrings(left[0], right[0]),
  );
  const packages = buildPackages(nextDependencies);
  writeProjectState(data, nextDependencies, packages);
  return packages.find((pkg) => pkg.name === name);
}

function commandAdd(spec) {
  const { name, version } = parseSpec(spec, 'add');
  const added = applyDependency(name, version);
  process.stdout.write(`added ${name}@${version} (${added.files.length} files)\n`);
}

function commandRemove(name) {
  validateName(name, 'package name');
  const { data, dependencies } = readManifestFile();
  if (!dependencies.some(([dependencyName]) => dependencyName === name)) {
    throw new CliError(`unknown dependency: ${name}`);
  }
  const nextDependencies = dependencies.filter(([dependencyName]) => dependencyName !== name);
  const packages = buildPackages(nextDependencies);
  writeProjectState(data, nextDependencies, packages);
  process.stdout.write(`removed ${name} (${packages.length} packages remain)\n`);
}

function commandLock() {
  const { dependencies } = readManifestFile();
  const packages = buildPackages(dependencies);
  writeJsonFile('opurom.lock', { version: 1, packages });
  process.stdout.write(`regenerated opurom.lock (${packages.length} packages)\n`);
}

function commandList() {
  const packages = readLockFile();
  const rows = [['NAME', 'VERSION', 'FILES', 'PATH']];
  for (const pkg of packages) {
    rows.push([pkg.name, pkg.version, String(pkg.files.length), pkg.path]);
  }
  const widths = rows[0].map((_, column) =>
    Math.max(...rows.map((row) => row[column].length)),
  );
  for (const row of rows) {
    process.stdout.write(
      `${row.map((cell, column) => cell.padEnd(widths[column])).join('  ').trimEnd()}\n`,
    );
  }
}

function manifestDriftErrors(dependencies, packages) {
  const expected = new Map(dependencies);
  const locked = new Map(packages.map((pkg) => [pkg.name, pkg.version]));
  const errors = [];
  for (const [name, version] of expected) {
    if (!locked.has(name)) {
      errors.push(`missing locked package: ${name}@${version}`);
    } else if (locked.get(name) !== version) {
      errors.push(`version drift: ${name} expected ${version}, lock has ${locked.get(name)}`);
    }
  }
  for (const [name, version] of locked) {
    if (!expected.has(name)) errors.push(`unexpected locked package: ${name}@${version}`);
  }
  return errors;
}

function verifyPackage(pkg) {
  const errors = [];
  if (packageDigest(pkg.files) !== pkg.sha256) {
    errors.push(`package sha256 drift: ${pkg.path}`);
  }
  try {
    const directory = resolveContained(
      pkg.path,
      `package path ${pkg.path}`,
      'directory',
    );
    const actual = walkFiles(pkg.path, directory.absolute).sort(compareStrings);
    const locked = pkg.files.map((file) => file.path).sort(compareStrings);
    if (!sameList(actual, locked)) errors.push(`file list drift: ${pkg.path}`);
  } catch (error) {
    errors.push(errorText(error));
  }
  for (const file of pkg.files) {
    try {
      const target = resolveContained(file.path, `locked file ${file.path}`, 'file');
      if (hashFile(target.absolute, file.path) !== file.sha256) {
        errors.push(`checksum mismatch: ${file.path}`);
      }
    } catch (error) {
      errors.push(errorText(error));
    }
  }
  return errors;
}

function report(checks) {
  for (const check of checks) {
    const passed = check.errors.length === 0;
    const detail = passed ? `  ${check.detail}` : '';
    process.stdout.write(`${passed ? 'PASS' : 'FAIL'}  ${check.label}${detail}\n`);
    for (const error of check.errors) process.stdout.write(`      ${error}\n`);
  }
  const passed = checks.filter((check) => check.errors.length === 0).length;
  process.stdout.write(`\n${passed}/${checks.length} checks passed\n`);
  if (passed !== checks.length) process.exitCode = 1;
}

function commandVerify() {
  let manifest;
  let packages;
  try {
    manifest = readManifestFile();
  } catch (error) {
    report([{ label: '<manifest>', detail: '', errors: [errorText(error)] }]);
    return;
  }
  try {
    packages = readLockFile();
  } catch (error) {
    report([{ label: '<lock>', detail: '', errors: [errorText(error)] }]);
    return;
  }
  const checks = [
    {
      label: '<manifest>',
      detail: 'dependencies match opurom.lock',
      errors: manifestDriftErrors(manifest.dependencies, packages),
    },
  ];
  for (const pkg of packages) {
    checks.push({
      label: `${pkg.name}@${pkg.version}`,
      detail: `${pkg.files.length} files`,
      errors: verifyPackage(pkg),
    });
  }
  report(checks);
}

function oneArgument(command, rest) {
  if (rest.length !== 1) throw new CliError(`${command} needs exactly one argument`, 2);
  return rest[0];
}

function noArguments(command, rest) {
  if (rest.length !== 0) throw new CliError(`${command} takes no arguments`, 2);
}

// --- signing -------------------------------------------------------------

// Signs every locked package file plus the lockfile itself.
function commandSign() {
  const packages = readLockFile();
  const { privateKey, publicKeyPath, created } = loadOrCreateKeypair(ROOT);
  const written = [];
  for (const pkg of packages) {
    for (const file of pkg.files) {
      const target = resolveContained(file.path, `locked file ${file.path}`, 'file');
      const bytes = readNoFollow(target.absolute, file.path);
      const signature = signBytes(privateKey, file.path, bytes);
      writeSignature(ROOT, file.path, signature);
      written.push(file.path);
    }
  }
  const lockBytes = readNoFollow(path.join(ROOT, 'opurom.lock'), 'opurom.lock');
  writeSignature(ROOT, 'opurom.lock', signBytes(privateKey, 'opurom.lock', lockBytes));
  written.push('opurom.lock');
  process.stdout.write(
    `signed ${written.length} files with ${path.basename(publicKeyPath)}${
      created ? ' (new keypair created)' : ''
    }\n`,
  );
}

// Verifies one detached signature against the file on disk.
function verifySignatureFile(publicKey, relativePath) {
  const signature = readSignature(ROOT, relativePath);
  if (!signature) {
    return [`missing signature: ${relativePath}${SIG_EXT}`];
  }
  let target;
  try {
    target = resolveContained(relativePath, `signed file ${relativePath}`, 'file');
  } catch (error) {
    return [errorText(error)];
  }
  const bytes = readNoFollow(target.absolute, relativePath);
  if (!verifyBytes(publicKey, relativePath, bytes, signature)) {
    return [`invalid signature: ${relativePath}${SIG_EXT}`];
  }
  return [];
}

function verifySignedPackages(packages) {
  let publicKey;
  try {
    publicKey = readPublicKey(ROOT);
  } catch (error) {
    return {
      checks: [{ label: '<signatures>', detail: '', errors: [error.message] }],
    };
  }
  const checks = [];
  for (const pkg of packages) {
    const errors = [];
    for (const file of pkg.files) {
      errors.push(...verifySignatureFile(publicKey, file.path));
    }
    checks.push({
      label: `${pkg.name}@${pkg.version}`,
      detail: `${pkg.files.length} files signed`,
      errors,
    });
  }
  const lockErrors = verifySignatureFile(publicKey, 'opurom.lock');
  checks.push({
    label: 'opurom.lock',
    detail: 'lockfile signed',
    errors: lockErrors,
  });
  return { checks };
}

function commandVerifySigned(packages) {
  const { checks } = verifySignedPackages(packages);
  report(checks);
}

// --- registry ------------------------------------------------------------

function registryUrl() {
  const raw = process.env.OPUROM_REGISTRY_URL || DEFAULT_REGISTRY_URL;
  return raw.endsWith('/') ? raw : `${raw}/`;
}

function packageFilesForPublish(name, version) {
  const pkg = collectPackage(name, version);
  return pkg;
}

async function commandRegistryServer(rest) {
  let port = 0;
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    let raw = null;
    if (argument === '--port') {
      raw = rest[index + 1];
      index += 1;
    } else if (argument.startsWith('--port=')) {
      raw = argument.slice('--port='.length);
    }
    if (raw === null || !/^\d+$/.test(raw)) {
      throw new CliError(`unknown option for registry-server: ${argument}`, 2);
    }
    const value = Number(raw);
    if (value > 65535) throw new CliError(`invalid port: ${raw}`);
    port = value;
  }
  const server = createRegistryServer(ROOT);
  const bound = await listenLoopback(server, port);
  process.stdout.write(`registry listening on http://127.0.0.1:${bound}\n`);
  const stop = async () => {
    await closeServer(server);
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function commandPublish(spec) {
  const { name, version } = parseSpec(spec, 'publish');
  const pkg = collectPackage(name, version);
  const base = registryUrl();
  for (const file of pkg.files) {
    const target = resolveContained(file.path, `registry file ${file.path}`, 'file');
    const bytes = readNoFollow(target.absolute, file.path);
    const digest = sha256(bytes);
    const fileName = file.path.slice(pkg.path.length + 1);
    const url = new URL(`packages/${name}/${version}/${fileName}`, base);
    const response = await request(url, {
      method: 'PUT',
      body: bytes,
      headers: { 'x-content-sha256': digest },
    });
    if (response.status !== 200 && response.status !== 201) {
      throw new CliError(
        `publish ${name}@${version} (${fileName}) failed with status ${response.status}: ${response.body
          .toString('utf8')
          .trim()}`,
      );
    }
    const result = JSON.parse(response.body.toString('utf8'));
    if (result.sha256 !== digest) {
      throw new CliError(`publish integrity mismatch for ${fileName}`);
    }
  }
  process.stdout.write(`published ${name}@${version} (${pkg.files.length} files) to ${base}\n`);
}

// Writes an installed file inside the project root, creating parent directories.
function writeInstalledFile(relative, bytes) {
  const parts = assertRelative(relative, `installed file ${relative}`);
  const absolute = path.resolve(ROOT, ...parts);
  assertInside(absolute, relative, `installed file ${relative}`);
  mkdirSync(path.dirname(absolute), { recursive: true });
  writeFileSync(absolute, bytes);
}

async function commandInstall(spec) {
  const { name, version } = parseSpec(spec, 'install');
  const base = registryUrl();
  const manifestUrl = new URL(`packages/${name}/${version}/`, base);
  const manifestResponse = expectOk(
    await request(manifestUrl),
    `install ${name}@${version} (package listing)`,
  );
  const listing = JSON.parse(manifestResponse.body.toString('utf8'));
  if (!Array.isArray(listing.files) || listing.files.length === 0) {
    throw new CliError(`registry returned no files for ${name}@${version}`);
  }
  const packageRelative = registryPath(name, version);
  for (const entry of listing.files) {
    const relative = path.posix.join(packageRelative, entry.path);
    const url = new URL(`packages/${name}/${version}/${entry.path}`, base);
    const response = expectOk(await request(url), `install ${name}@${version} (${entry.path})`);
    assertIntegrity(response, entry.sha256, `install ${name}@${version} (${entry.path})`);
    writeInstalledFile(relative, response.body);
  }
  const added = applyDependency(name, version);
  process.stdout.write(
    `installed ${name}@${version} (${added.files.length} files) from ${base}\n`,
  );
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (!command) {
    process.stdout.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  if (command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  if (command === 'init') {
    commandInit(oneArgument(command, rest));
  } else if (command === 'add') {
    commandAdd(oneArgument(command, rest));
  } else if (command === 'remove') {
    commandRemove(oneArgument(command, rest));
  } else if (command === 'list') {
    noArguments(command, rest);
    commandList();
  } else if (command === 'verify') {
    if (rest.length === 0) {
      commandVerify();
    } else if (rest.length === 1 && rest[0] === '--signed') {
      let packages;
      try {
        packages = readLockFile();
      } catch (error) {
        report([{ label: '<lock>', detail: '', errors: [errorText(error)] }]);
        return;
      }
      commandVerifySigned(packages);
    } else {
      throw new CliError(`verify takes no arguments or --signed`, 2);
    }
  } else if (command === 'lock') {
    noArguments(command, rest);
    commandLock();
  } else if (command === 'sign') {
    noArguments(command, rest);
    commandSign();
  } else if (command === 'registry-server') {
    await commandRegistryServer(rest);
  } else if (command === 'publish') {
    await commandPublish(oneArgument(command, rest));
  } else if (command === 'install') {
    await commandInstall(oneArgument(command, rest));
  } else {
    throw new CliError(`unknown command: ${command}\n${USAGE}`, 2);
  }
}

main(process.argv.slice(2)).catch((error) => {
  const code = error instanceof CliError ? error.code : 1;
  const text =
    error instanceof CliError || error instanceof SigningError || error instanceof HttpError
      ? error.message
      : error?.stack ?? String(error);
  process.stderr.write(`error: ${text}\n`);
  process.exitCode = code;
});
