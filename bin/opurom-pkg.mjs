#!/usr/bin/env node
// Opurom package CLI: local registry and GitHub-backed signed releases. Node builtins only.
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
  ArchiveError,
  MAX_ARCHIVE_BYTES,
  assertSafePath,
  createPackageArchive,
  readPackageArchive,
} from '../lib/package-archive.mjs';
import {
  GitHubRegistryError,
  MAX_BUNDLE_BYTES,
  MAX_CHANNEL_MANIFEST_BYTES,
  RegistryNetworkError,
  assetNames,
  createGithubMockServer,
  createGithubRegistry,
  parseRepository,
  parseTrainTag,
} from '../lib/github-registry.mjs';
import {
  closeServer,
  createRegistryServer,
  listenLoopback,
} from '../lib/registry.mjs';
import { HttpError, assertIntegrity, expectOk, request } from '../lib/http-client.mjs';
import {
  compareVersionOrder,
  compareVersions,
  highestSatisfying,
  parseRange,
  parseVersion,
  satisfies,
} from '../lib/semver.mjs';

// Mutations must never fall back to the tool's own repo: an uninitialized
// working directory would otherwise silently rewrite the packaged manifest.
const MUTATING = new Set([
  'init',
  'add',
  'remove',
  'install',
  'lock',
  'sign',
  'publish',
  'update',
  'channel-sign',
]);

function resolveRoot() {
  const current = realpathSync(process.cwd());
  const command = process.argv[2];
  if (MUTATING.has(command)) return current;
  if (existsSync(path.join(current, 'opurom.json'))) return current;
  const packaged = path.resolve(import.meta.dirname, '..');
  if (existsSync(path.join(current, 'registry'))) return current;
  if (existsSync(path.join(packaged, 'opurom.json'))) return packaged;
  return current;
}

const ROOT = resolveRoot();
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const READ_FLAGS = constants.O_RDONLY | NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | NOFOLLOW;
const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
// Local mock registry only: loopback HTTP, no TLS, no remote hosts.
const DEFAULT_REGISTRY_URL = 'http://127.0.0.1:4873';
const CHANNEL_MANIFEST = 'update-channel.json';

const USAGE = `usage: opurom-pkg <command>

  init <name>             write opurom.json and an empty opurom.lock
  add <name>@<contract>       resolve from registry/ and refresh opurom.lock
  remove <name>           remove a dependency and refresh opurom.lock
  list                    show packages in opurom.lock
  show <name>             show one locked package's metadata
  outdated                compare opurom.lock against registry/ versions
  verify [--signed]       recompute SHA-256 of every locked file
  lock [--check]          regenerate or check deterministic opurom.lock
  sign                    write detached Ed25519 signatures
  registry-server [--port N]       serve registry/ on loopback HTTP
  github-registry-server [--port N] serve a GitHub API mock on loopback
  publish <name>@<version>         publish over loopback HTTP
  install <name>@<version>         install over loopback HTTP
  update check --github <owner/repo> --current x.y.z
                                   report a newer signed channel release
  update fetch --github <owner/repo> --current x.y.z --out <dir>
                                   [--version x.y.z] fetch a verified bundle,
                                   never install
  channel-sign <manifest>          sign update-channel.json with the project keypair
  channel-verify <manifest>        verify an update-channel.json signature
  search --github <owner/repo> [name]    list signed Release assets
  publish --github <owner/repo> <name>@<version>
  install --github <owner/repo> <name>@<version>

Run from the project root. publish/install use exact x.y.z versions; add also
accepts SemVer 2.0 comparator ranges such as ">=1.0.0 <2.0.0", which pin the
highest stable version in opurom.lock. Registry packages may declare their own
dependencies; the reachable tree resolves to one consistent version per
package, and conflicting requirements are reported with their requirers.
install also fetches every transitive dependency the local registry cannot
satisfy. Every lock write records the SHA-256 of opurom.json; verify --signed
compares the manifest with that signed digest, and lock refreshes it after a
legitimate edit.
Local publish/install use Opurom_REGISTRY_URL (loopback HTTP only).
--github uses https://api.github.com, or Opurom_GITHUB_API_URL for a loopback mock.
Publishing reads OPR_GITHUB_TOKEN from the environment only.`;

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

// The publish token is read from this single environment variable and is never persisted.
function githubToken() {
  return process.env.OPR_GITHUB_TOKEN || null;
}

function redactToken(text) {
  const token = githubToken();
  return token ? text.split(token).join('[REDACTED]') : text;
}

function githubRegistry() {
  return createGithubRegistry({ token: githubToken() });
}

function githubArgs(command, rest, expected) {
  if (rest[0] !== '--github' || typeof rest[1] !== 'string' || rest[1].length === 0) {
    throw new CliError(`${command} needs --github <owner/repo>`, 2);
  }
  try {
    parseRepository(rest[1]);
  } catch (error) {
    throw new CliError(errorText(error), 2);
  }
  const positional = rest.slice(2);
  const allowed = Array.isArray(expected) ? expected : [expected];
  if (!allowed.includes(positional.length)) {
    throw new CliError(`${command} --github needs ${allowed.join(' or ')} positional argument(s)`, 2);
  }
  return { repository: rest[1], positional };
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

// Hashes the manifest bytes on disk, so any edit (not just a dependency change) is visible.
function manifestSha256() {
  return hashFile(path.join(ROOT, 'opurom.json'), 'opurom.json');
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
  if (!parseVersion(version)) {
    throw new CliError(
      `invalid version for ${label}: ${String(version)}; use SemVer 2.0 x.y.z`,
    );
  }
}

function validateDependencySpec(contract, label) {
  if (!parseRange(contract)) {
    throw new CliError(
      `invalid version for ${label}: ${String(contract)}; use SemVer 2.0 x.y.z or a comparator range`,
    );
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
    validateDependencySpec(version, `dependency ${name}`);
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
  // Older locks may omit it; verify --signed refuses those instead of trusting them.
  if (
    data.manifestSha256 !== undefined &&
    (typeof data.manifestSha256 !== 'string' || !SHA256_RE.test(data.manifestSha256))
  ) {
    throw new CliError('invalid manifestSha256 in opurom.lock');
  }
  const packages = data.packages.map(validateLockedPackage);
  const sorted = [...packages].sort(comparePackages);
  if (!packages.every((pkg, index) => pkg === sorted[index])) {
    throw new CliError('opurom.lock packages are not sorted');
  }
  if (new Set(packages.map((pkg) => pkg.name)).size !== packages.length) {
    throw new CliError('duplicate locked package name');
  }
  return { manifestSha256: data.manifestSha256 ?? null, packages };
}

function readLockData() {
  if (!existsSync(path.join(ROOT, 'opurom.lock'))) {
    throw new CliError('missing opurom.lock; run lock first');
  }
  return validateLock(readJsonAt('opurom.lock', 'lockfile'));
}

function readLockFile() {
  return readLockData().packages;
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

// Requirement edges for one registry version, validated and name-sorted.
// Read-only resolution tolerates a version directory with no manifest;
// collecting files for the lock still refuses it.
function registryDependencies(name, version) {
  const metadataRelative = path.posix.join(registryPath(name, version), 'opurom-pkg.json');
  let metadata;
  try {
    metadata = readJsonAt(metadataRelative, `registry manifest for ${name}@${version}`);
  } catch (error) {
    if (error instanceof CliError && error.message.startsWith('missing ')) return [];
    throw error;
  }
  if (!plainObject(metadata)) {
    throw new CliError(`registry manifest must be a JSON object: ${metadataRelative}`);
  }
  if (metadata.dependencies === undefined) return [];
  if (!plainObject(metadata.dependencies)) {
    throw new CliError(`registry manifest dependencies must be an object: ${metadataRelative}`);
  }
  const dependencies = Object.entries(metadata.dependencies).map(([dependencyName, contract]) => {
    validateName(dependencyName, 'dependency name');
    validateDependencySpec(contract, `dependency ${dependencyName} of ${name}@${version}`);
    return [dependencyName, contract];
  });
  dependencies.sort((left, right) => compareStrings(left[0], right[0]));
  return dependencies;
}

// Only version directories are candidates; a malformed one is a hard error so
// a leading-zero version can never win by accident.
function registryVersions(name) {
  const relative = `registry/${name}`;
  const directory = resolveContained(relative, `registry for ${name}`, 'directory');
  const versions = [];
  for (const entry of readdirSync(directory.absolute, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) {
      throw new CliError(`unsafe registry path: ${relative}/${entry.name} (symlink rejected)`);
    }
    if (!entry.isDirectory()) continue;
    if (!parseVersion(entry.name)) {
      throw new CliError(`invalid version for ${name}: ${entry.name}; use SemVer 2.0 x.y.z`);
    }
    versions.push(entry.name);
  }
  return versions;
}

// The reachable dependency tree resolves to one version per package name: the
// requirements that reach a name accumulate, and a version must satisfy all of
// them. Search walks names in discovery order, tries candidates highest first
// and backtracks when a later requirement invalidates an earlier choice.
// Candidate and requirement lists are sorted, so registry directory order
// never changes the outcome.
// shortcut: the step budget bounds pathological backtracking, raise it for graphs that outgrow it.
const MAX_RESOLUTION_STEPS = 20000;

function resolveTree(rootDependencies) {
  const edges = new Map();
  const order = [];
  const chosen = new Map();
  let steps = 0;
  let conflict = null;

  function record(name, contract, by) {
    let requirements = edges.get(name);
    if (requirements === undefined) {
      requirements = [];
      edges.set(name, requirements);
      order.push(name);
    }
    requirements.push({ contract, by });
  }

  function snapshot() {
    return {
      order: [...order],
      edges: new Map([...edges].map(([name, list]) => [name, [...list]])),
      chosen: new Map(chosen),
    };
  }

  function restore(state) {
    order.length = 0;
    order.push(...state.order);
    edges.clear();
    for (const [name, list] of state.edges) edges.set(name, list);
    chosen.clear();
    for (const [name, version] of state.chosen) chosen.set(name, version);
  }

  // Registry versions satisfying every recorded requirement, highest first.
  // An exact pin whose package is absent reports the missing path directly.
  function candidates(name) {
    const requirements = edges.get(name);
    const pinned = requirements.find(({ contract }) => parseRange(contract).exact);
    if (pinned !== undefined) {
      const version = parseRange(pinned.contract).version.raw;
      const expected = registryPath(name, version);
      if (!existsSync(path.join(ROOT, expected))) {
        throw new CliError(`unknown local package: ${name}@${version} (expected ${expected})`);
      }
    }
    const ranges = requirements.map(({ contract }) => parseRange(contract));
    return registryVersions(name)
      .filter((version) => ranges.every((range) => satisfies(version, range)))
      .sort((left, right) => compareVersionOrder(right, left));
  }

  function choiceHolds(name) {
    const version = chosen.get(name);
    return edges.get(name).every(({ contract }) => satisfies(version, parseRange(contract)));
  }

  function noteConflict(name, index) {
    if (conflict === null || index > conflict.index) {
      conflict = { name, index, requirements: [...edges.get(name)] };
    }
  }

  function search(index) {
    if (index === order.length) return true;
    const name = order[index];
    const versions = candidates(name);
    if (versions.length === 0) {
      noteConflict(name, index);
      return false;
    }
    for (const version of versions) {
      steps += 1;
      if (steps > MAX_RESOLUTION_STEPS) {
        throw new CliError(`dependency resolution exceeded ${MAX_RESOLUTION_STEPS} steps`);
      }
      const before = snapshot();
      chosen.set(name, version);
      let consistent = true;
      for (const [dependency, contract] of registryDependencies(name, version)) {
        record(dependency, contract, `${name}@${version}`);
        if (chosen.has(dependency) && !choiceHolds(dependency)) {
          consistent = false;
          if (candidates(dependency).length === 0) {
            noteConflict(dependency, order.indexOf(dependency));
          }
          break;
        }
      }
      if (consistent && search(index + 1)) return true;
      restore(before);
    }
    return false;
  }

  for (const [name, contract] of rootDependencies) record(name, contract, 'opurom.json');
  if (!search(0)) {
    if (conflict !== null) {
      const lines = [`dependency conflict: ${conflict.name}`];
      for (const { contract, by } of conflict.requirements) {
        lines.push(`  ${by} requires ${contract}`);
      }
      lines.push(`  no version of ${conflict.name} satisfies all constraints`);
      throw new CliError(lines.join('\n'));
    }
    throw new CliError('dependency resolution failed: no consistent version set');
  }
  return order.map((name) => ({ name, version: chosen.get(name) }));
}

// The lock records resolved files only; requirement edges stay in the manifests.
function buildPackages(dependencies) {
  return resolveTree(dependencies)
    .map(({ name, version }) => collectPackage(name, version))
    .sort(comparePackages);
}

// The signed lockfile attests to the manifest bytes that produced it.
function lockData(packages) {
  return { version: 1, manifestSha256: manifestSha256(), packages };
}

function writeLock(packages) {
  writeJsonFile('opurom.lock', lockData(packages));
}

// shortcut: two atomic replacements are not one transaction; verify detects drift, upgrade for concurrent writers.
function writeProjectState(manifestData, dependencies, packages) {
  const nextManifest = {
    ...manifestData,
    dependencies: Object.fromEntries(dependencies),
  };
  writeJsonFile('opurom.json', nextManifest);
  writeLock(packages);
}

function parseSpec(contract, command = 'add', options = {}) {
  const at = contract.lastIndexOf('@');
  if (at <= 0 || at === contract.length - 1) {
    throw new CliError(`${command} needs <name>@<version>, for example opurom-ui@0.1.0`);
  }
  const name = contract.slice(0, at);
  const version = contract.slice(at + 1);
  validateName(name, 'package name');
  if (options.allowRange) {
    validateDependencySpec(version, `package ${name}`);
  } else {
    validateVersion(version, `package ${name}`);
  }
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
  writeLock([]);
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

function commandAdd(contract) {
  const { name, version } = parseSpec(contract, 'add', { allowRange: true });
  const added = applyDependency(name, version);
  process.stdout.write(`added ${name}@${added.version} (${added.files.length} files)\n`);
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
  writeLock(packages);
  process.stdout.write(`regenerated opurom.lock (${packages.length} packages)\n`);
}

// Byte comparison catches drift that hash checks miss, such as a reformatted lockfile.
function commandLockCheck() {
  const lockPath = path.join(ROOT, 'opurom.lock');
  if (!existsSync(lockPath)) {
    throw new CliError('missing opurom.lock; run lock first');
  }
  const { dependencies } = readManifestFile();
  const packages = buildPackages(dependencies);
  const expected = stableJson(lockData(packages));
  const actual = readNoFollow(lockPath, 'opurom.lock', 'utf8');
  if (actual !== expected) {
    throw new CliError('opurom.lock is stale; run lock to regenerate it');
  }
  process.stdout.write(`opurom.lock is up to date (${packages.length} packages)\n`);
}

function printRows(rows) {
  const widths = rows[0].map((_, column) =>
    Math.max(...rows.map((row) => row[column].length)),
  );
  for (const row of rows) {
    process.stdout.write(
      `${row.map((cell, column) => cell.padEnd(widths[column])).join('  ').trimEnd()}\n`,
    );
  }
}

function commandList() {
  const packages = readLockFile();
  const rows = [['NAME', 'VERSION', 'FILES', 'PATH']];
  for (const pkg of packages) {
    rows.push([pkg.name, pkg.version, String(pkg.files.length), pkg.path]);
  }
  printRows(rows);
}

// One locked package, resolved purely from opurom.lock (name, version, package
// digest, sorted file checksums) so an audit needs no registry access.
function commandShow(name) {
  validateName(name, 'package name');
  const pkg = readLockFile().find((entry) => entry.name === name);
  if (!pkg) throw new CliError(`unknown locked package: ${name}`);
  const rows = [['NAME', 'VERSION', 'FILES', 'PATH', 'SHA256']];
  rows.push([pkg.name, pkg.version, String(pkg.files.length), pkg.path, pkg.sha256]);
  printRows(rows);
  process.stdout.write('\nFILES\n');
  for (const file of pkg.files) {
    process.stdout.write(`${file.sha256}  ${file.path}\n`);
  }
}

// Compares every locked version with what the dependency tree resolves to today
// and with the highest stable registry version. Read-only, so the byte-stable
// lockfile contract is untouched; rows keep the lock's name order.
function commandOutdated() {
  const manifest = readManifestFile();
  const lockedPackages = readLockFile();
  // The latest column reads registry/ first, so a removed package keeps its
  // original error before tree resolution reports anything else.
  const latest = new Map(
    lockedPackages.map((pkg) => [
      pkg.name,
      highestSatisfying(parseRange('>=0.0.0'), registryVersions(pkg.name)) ?? '-',
    ]),
  );
  const wanted = new Map(
    resolveTree(manifest.dependencies).map((entry) => [entry.name, entry.version]),
  );
  const rows = [['NAME', 'LOCKED', 'WANTED', 'LATEST']];
  for (const pkg of lockedPackages) {
    const wantedVersion = wanted.get(pkg.name) ?? '-';
    if (pkg.version === wantedVersion && pkg.version === latest.get(pkg.name)) continue;
    rows.push([pkg.name, pkg.version, wantedVersion, latest.get(pkg.name)]);
  }
  if (rows.length === 1) {
    process.stdout.write('all locked packages are up to date\n');
    return;
  }
  printRows(rows);
}

function manifestDriftErrors(dependencies, packages) {
  const expected = new Map(dependencies);
  const locked = new Map(packages.map((pkg) => [pkg.name, pkg.version]));
  const errors = [];
  for (const [name, contract] of expected) {
    if (!locked.has(name)) {
      errors.push(`missing locked package: ${name}@${contract}`);
      continue;
    }
    const range = parseRange(contract);
    if (range.exact && locked.get(name) !== contract) {
      errors.push(`version drift: ${name} expected ${contract}, lock has ${locked.get(name)}`);
    }
  }
  // The tree pass owns range contracts: backtracking may pin below the
  // standalone highest version when another requirement forbids it.
  if (errors.length > 0) return errors;
  let resolved;
  try {
    resolved = resolveTree(dependencies);
  } catch (error) {
    return [errorText(error)];
  }
  const resolvedNames = new Set(resolved.map((entry) => entry.name));
  for (const { name, version } of resolved) {
    if (!locked.has(name)) {
      errors.push(`missing locked package: ${name}@${version} (transitive)`);
      continue;
    }
    if (locked.get(name) !== version) {
      errors.push(`version drift: ${name} expected ${version}, lock has ${locked.get(name)}`);
    }
  }
  for (const [name, version] of locked) {
    if (!resolvedNames.has(name)) errors.push(`unexpected locked package: ${name}@${version}`);
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

// The digest lives in the signed lockfile, so it is only trusted after that signature verifies.
function manifestIntegrityErrors(expectedSha256) {
  if (expectedSha256 === null) {
    return ['missing manifestSha256 in opurom.lock; run lock to record it'];
  }
  try {
    if (manifestSha256() !== expectedSha256) {
      return ['manifest digest mismatch: opurom.json; run lock to refresh it'];
    }
  } catch (error) {
    return [errorText(error)];
  }
  return [];
}

function verifySignedPackages(lock) {
  let publicKey;
  try {
    publicKey = readPublicKey(ROOT);
  } catch (error) {
    return {
      checks: [{ label: '<signatures>', detail: '', errors: [error.message] }],
    };
  }
  const checks = [];
  for (const pkg of lock.packages) {
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
  if (lockErrors.length === 0) {
    lockErrors.push(...manifestIntegrityErrors(lock.manifestSha256));
  }
  checks.push({
    label: 'opurom.lock',
    detail: 'lockfile signed; manifest digest checked',
    errors: lockErrors,
  });
  return { checks };
}

function commandVerifySigned(lock) {
  const { checks } = verifySignedPackages(lock);
  report(checks);
}

// --- registry ------------------------------------------------------------

function registryUrl() {
  const raw = process.env.Opurom_REGISTRY_URL || DEFAULT_REGISTRY_URL;
  return raw.endsWith('/') ? raw : `${raw}/`;
}

function packageFilesForPublish(name, version) {
  const pkg = collectPackage(name, version);
  return pkg;
}

async function commandRegistryServer(rest, github = false) {
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
      throw new CliError(`unknown option for ${github ? 'github-registry-server' : 'registry-server'}: ${argument}`, 2);
    }
    const value = Number(raw);
    if (value > 65535) throw new CliError(`invalid port: ${raw}`);
    port = value;
  }
  const server = github ? createGithubMockServer() : createRegistryServer(ROOT);
  const bound = await listenLoopback(server, port);
  process.stdout.write(
    `${github ? 'github registry' : 'registry'} listening on http://127.0.0.1:${bound}\n`,
  );
  const stop = async () => {
    await closeServer(server);
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function commandPublish(contract) {
  const { name, version } = parseSpec(contract, 'publish');
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
function writeInstalledFile(relative, bytes, expectedSha256 = null) {
  const parts = assertRelative(relative, `installed file ${relative}`);
  const absolute = path.resolve(ROOT, ...parts);
  assertInside(absolute, relative, `installed file ${relative}`);
  if (expectedSha256 !== null && sha256(bytes) !== expectedSha256) {
    throw new CliError(`sha256 mismatch before writing ${relative}`);
  }
  let current = ROOT;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    let stat;
    try {
      stat = lstatSync(current);
    } catch (error) {
      if (error.code === 'ENOENT') break;
      throw new CliError(`cannot stat ${relative}: ${error.message}`);
    }
    if (stat.isSymbolicLink()) {
      throw new CliError(`unsafe installed file: ${relative} (symlink rejected)`);
    }
    if (!stat.isDirectory()) throw new CliError(`not a directory: ${relative}`);
  }
  mkdirSync(path.dirname(absolute), { recursive: true });
  let fd;
  try {
    fd = openSync(absolute, WRITE_FLAGS, 0o600);
    writeFileSync(fd, bytes);
  } catch (error) {
    if (error.code === 'ELOOP') throw new CliError(`unsafe installed file: ${relative} (symlink rejected)`);
    throw new CliError(`cannot write ${relative}: ${error.message}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// The best local registry version satisfying a contract, or null when the
// registry (or every version in it) cannot satisfy it.
function localSatisfying(name, contract) {
  if (!existsSync(path.join(ROOT, 'registry', name))) return null;
  return highestSatisfying(parseRange(contract), registryVersions(name));
}

// One remote version satisfying a contract, or an honest failure. Remote
// versions are validated like local registry directories.
function pickRemote(name, contract, versions) {
  for (const version of versions) validateVersion(version, name);
  const winner = highestSatisfying(parseRange(contract), versions);
  if (winner === null) throw new CliError(`no remote version of ${name} satisfies ${contract}`);
  return winner;
}

async function remoteHttpVersions(base, name) {
  const url = new URL(`packages/${name}/`, base);
  const response = expectOk(await request(url), `install ${name} (version list)`);
  const listing = JSON.parse(response.body.toString('utf8'));
  if (!plainObject(listing) || !Array.isArray(listing.versions)) {
    throw new CliError(`registry returned an invalid version list for ${name}`);
  }
  return listing.versions;
}

// Installs the reachable dependency closure: every requirement the local
// registry cannot satisfy is resolved remotely and fetched, then its own
// edges are followed. Returns fetched packages as name@version, in order.
async function installClosure(startEdges, resolveRemote, fetchPackage) {
  const ensured = new Set();
  const queue = [...startEdges];
  const fetched = [];
  while (queue.length > 0) {
    const [name, contract] = queue.shift();
    const seen = `${name}@${contract}`;
    if (ensured.has(seen)) continue;
    ensured.add(seen);
    let version = localSatisfying(name, contract);
    if (version === null) {
      version = await resolveRemote(name, contract);
      await fetchPackage(name, version);
      fetched.push(`${name}@${version}`);
    }
    queue.push(...registryDependencies(name, version));
  }
  return fetched;
}

async function fetchRegistryPackage(name, version, base) {
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
}

async function commandInstall(contract) {
  const { name, version } = parseSpec(contract, 'install');
  const base = registryUrl();
  await fetchRegistryPackage(name, version, base);
  const fetched = await installClosure(
    registryDependencies(name, version),
    async (dependency, range) => {
      return pickRemote(dependency, range, await remoteHttpVersions(base, dependency));
    },
    (dependency, wanted) => fetchRegistryPackage(dependency, wanted, base),
  );
  const added = applyDependency(name, version);
  process.stdout.write(
    `installed ${name}@${version} (${added.files.length} files) from ${base}\n`,
  );
  if (fetched.length > 0) {
    process.stdout.write(`fetched transitive: ${fetched.join(' ')}\n`);
  }
}

async function commandPublishGithub(repository, contract) {
  const token = githubToken();
  if (!token) {
    process.stdout.write('SKIP missing OPR_GITHUB_TOKEN; no GitHub Release was created\n');
    return;
  }
  const { name, version } = parseSpec(contract, 'publish');
  const pkg = collectPackage(name, version);
  const files = pkg.files.map((file) => {
    const target = resolveContained(file.path, `registry file ${file.path}`, 'file');
    const bytes = readNoFollow(target.absolute, file.path);
    const relative = assertSafePath(file.path.slice(pkg.path.length + 1));
    if (sha256(bytes) !== file.sha256) throw new CliError(`local sha256 mismatch: ${file.path}`);
    return { path: relative, bytes, sha256: file.sha256 };
  });
  const archive = createPackageArchive({ name, version, files });
  if (archive.length > MAX_ARCHIVE_BYTES) throw new CliError('archive exceeds bounded size');
  const { privateKey } = loadOrCreateKeypair(ROOT);
  const names = assetNames(name, version);
  const signature = signBytes(privateKey, names.archive, archive);
  const result = await createGithubRegistry({ token }).publish({
    repository,
    name,
    version,
    archive,
    signature,
    digest: sha256(archive),
  });
  process.stdout.write(
    `published ${name}@${version} release=${result.releaseUrl} assets=${result.asset},${result.signature}\n`,
  );
}

async function commandSearchGithub(repository, positional) {
  const name = positional[0] ?? null;
  if (name !== null) validateName(name, 'package name');
  const rows = await githubRegistry().search({ repository, name });
  if (rows.length === 0) {
    process.stdout.write(`no signed packages found in ${repository}\n`);
    return;
  }
  for (const row of rows) {
    process.stdout.write(
      `${row.name}@${row.version} release=${row.releaseUrl} asset=${row.asset}\n`,
    );
  }
}

// Downloads and verifies one signed package archive, then writes its files.
// Both the requested package and every fetched transitive package take this path.
async function fetchGithubPackage(repository, name, version) {
  const payload = await githubRegistry().download({ repository, name, version });
  const names = assetNames(name, version);
  const publicKey = readPublicKey(ROOT);
  let signed = false;
  try {
    signed = verifyBytes(publicKey, names.archive, payload.archive, payload.signature);
  } catch {
    signed = false;
  }
  if (!signed) throw new CliError(`invalid signature: ${names.signature}`);
  const digest = sha256(payload.archive);
  if (digest !== payload.digest) {
    throw new CliError(
      `sha256 mismatch: ${names.archive} (expected ${payload.digest}, got ${digest})`,
    );
  }
  const { files } = readPackageArchive(payload.archive, { name, version });
  const packageRelative = registryPath(name, version);
  for (const file of files) {
    const relative = path.posix.join(packageRelative, assertSafePath(file.path));
    writeInstalledFile(relative, file.bytes, file.sha256);
  }
  return payload;
}

async function commandInstallGithub(repository, contract) {
  const { name, version } = parseSpec(contract, 'install');
  const payload = await fetchGithubPackage(repository, name, version);
  const fetched = await installClosure(
    registryDependencies(name, version),
    async (dependency, range) => {
      const rows = await githubRegistry().search({ repository, name: dependency });
      return pickRemote(dependency, range, rows.map((row) => row.version));
    },
    (dependency, wanted) => fetchGithubPackage(repository, dependency, wanted),
  );
  const added = applyDependency(name, version);
  process.stdout.write(
    `installed ${name}@${version} (${added.files.length} files) from ${payload.releaseUrl} (${payload.asset})\n`,
  );
  if (fetched.length > 0) {
    process.stdout.write(`fetched transitive: ${fetched.join(' ')}\n`);
  }
}

// --- OTA update channel ---------------------------------------------------

// Flag-only parser for the update commands; positional arguments are none.
function updateFlags(command, rest, names) {
  const booleans = ['allow-downgrade'];
  const values = new Map();
  for (let index = 0; index < rest.length; index += 1) {
    const match = /^--([a-z-]+)$/.exec(rest[index]);
    if (!match || !names.includes(match[1])) {
      throw new CliError(`unknown option for ${command}: ${rest[index]}`, 2);
    }
    let value;
    if (booleans.includes(match[1])) {
      value = 'true';
    } else {
      value = rest[index + 1];
      index += 1;
      if (value === undefined) {
        throw new CliError(`${command} --${match[1]} needs a value`, 2);
      }
    }
    if (values.has(match[1])) throw new CliError(`duplicate option --${match[1]}`, 2);
    values.set(match[1], value);
  }
  return values;
}

// The channel head is the newest release-train tag. Package tags and drafts
// are not channel candidates.
function pickChannelRelease(releases) {
  const tagged = releases
    .map((release) => ({ ...release, version: parseTrainTag(release.tag)?.version ?? null }))
    .filter((release) => release.version !== null)
    .sort((left, right) => compareVersionOrder(right.version, left.version));
  return tagged[0] ?? null;
}

function parseChannelManifest(bytes, tag) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new CliError(`invalid channel manifest: ${CHANNEL_MANIFEST}`);
  }
  if (!plainObject(manifest) || manifest.version !== 1) {
    throw new CliError(`unsupported channel manifest version in ${CHANNEL_MANIFEST}`);
  }
  for (const field of ['channel', 'latest', 'tag', 'bundle']) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) {
      throw new CliError(`channel manifest ${field} must be a non-empty string`);
    }
  }
  if (typeof manifest.bundleSha256 !== 'string' || !SHA256_RE.test(manifest.bundleSha256)) {
    throw new CliError('invalid bundleSha256 in channel manifest');
  }
  if (manifest.tag !== tag) {
    throw new CliError(`channel manifest tag ${manifest.tag} does not match release tag ${tag}`);
  }
  if (!parseVersion(manifest.latest) || manifest.latest !== parseTrainTag(tag).version) {
    throw new CliError(
      `channel manifest latest ${manifest.latest} does not match release tag ${tag}`,
    );
  }
  assertRelative(manifest.bundle, 'bundle asset');
  return manifest;
}

// Trust order per the lockfile spec: the manifest signature comes first, so
// the recorded bundle digest is only trusted after it verifies.
async function loadVerifiedManifest(registry, repository, tag) {
  const manifest = await registry.downloadReleaseAsset({
    repository,
    tag,
    asset: CHANNEL_MANIFEST,
    maximum: MAX_CHANNEL_MANIFEST_BYTES,
  });
  const signature = await registry.downloadReleaseAsset({
    repository,
    tag,
    asset: `${CHANNEL_MANIFEST}.sig`,
    maximum: MAX_CHANNEL_MANIFEST_BYTES,
  });
  const publicKey = readPublicKey(ROOT);
  if (!verifyBytes(publicKey, CHANNEL_MANIFEST, manifest.bytes, signature.bytes)) {
    throw new CliError(`invalid signature: ${CHANNEL_MANIFEST}.sig`);
  }
  return { ...parseChannelManifest(manifest.bytes, tag), bytes: manifest.bytes, signature: signature.bytes };
}

async function resolveChannelTarget(registry, repository, requested) {
  const releases = await registry.releases({ repository });
  const release = requested === null
    ? pickChannelRelease(releases)
    : releases.find((entry) => parseTrainTag(entry.tag)?.version === requested) ?? null;
  if (release === null) {
    throw new CliError(
      requested === null
        ? `no release train tags found in ${repository}`
        : `no release for version ${requested} in ${repository}`,
    );
  }
  const manifest = await loadVerifiedManifest(registry, repository, release.tag);
  return { release, manifest };
}

async function commandUpdateCheck(rest) {
  const flags = updateFlags('update check', rest, ['github', 'current']);
  const repository = flags.get('github');
  const current = flags.get('current');
  if (!repository) throw new CliError('update check needs --github <owner/repo>', 2);
  if (!current) throw new CliError('update check needs --current <x.y.z>', 2);
  if (!parseVersion(current)) throw new CliError(`invalid current version: ${current}`);
  const registry = githubRegistry();
  const { release, manifest } = await resolveChannelTarget(registry, repository, null);
  if (compareVersions(manifest.latest, current) <= 0) {
    process.stdout.write('already up to date\n');
    return;
  }
  printRows([
    ['LATEST', 'CURRENT', 'TAG', 'BUNDLE', 'SHA256'],
    [manifest.latest, current, release.tag, manifest.bundle, manifest.bundleSha256],
  ]);
}

async function commandUpdateFetch(rest) {
  const flags = updateFlags('update fetch', rest, [
    'github',
    'current',
    'version',
    'out',
    'allow-downgrade',
  ]);
  const repository = flags.get('github');
  const current = flags.get('current');
  const out = flags.get('out');
  const requested = flags.get('version') ?? null;
  if (!repository) throw new CliError('update fetch needs --github <owner/repo>', 2);
  if (!current) throw new CliError('update fetch needs --current <x.y.z>', 2);
  if (!parseVersion(current)) throw new CliError(`invalid current version: ${current}`);
  if (!out) throw new CliError('update fetch needs --out <directory>', 2);
  assertRelative(out, 'output directory');
  if (requested !== null && !parseVersion(requested)) {
    throw new CliError(`invalid requested version: ${requested}`);
  }
  const registry = githubRegistry();
  const { release, manifest } = await resolveChannelTarget(registry, repository, requested);
  const target = requested ?? manifest.latest;
  if (compareVersions(target, current) < 0 && !flags.has('allow-downgrade')) {
    throw new CliError(
      `refusing downgrade: requested ${target} < current ${current} (use --allow-downgrade)`,
    );
  }
  if (compareVersions(target, current) === 0) {
    process.stdout.write('already up to date\n');
    return;
  }
  const bundle = await registry.downloadReleaseAsset({
    repository,
    tag: release.tag,
    asset: manifest.bundle,
    maximum: MAX_BUNDLE_BYTES,
  });
  const digest = sha256(bundle.bytes);
  if (digest !== manifest.bundleSha256) {
    throw new CliError(
      `sha256 mismatch: ${manifest.bundle} (expected ${manifest.bundleSha256}, got ${digest})`,
    );
  }
  // Every check has passed; the three channel files are written last.
  writeInstalledFile(path.posix.join(out, CHANNEL_MANIFEST), manifest.bytes);
  writeInstalledFile(path.posix.join(out, `${CHANNEL_MANIFEST}.sig`), manifest.signature);
  writeInstalledFile(path.posix.join(out, manifest.bundle), bundle.bytes, manifest.bundleSha256);
  process.stdout.write(
    `fetched ${manifest.latest} bundle ${manifest.bundle} (${bundle.bytes.length} bytes) to ${out}\n`,
  );
}

function commandChannelSign(relative) {
  assertRelative(relative, 'channel manifest');
  const file = resolveContained(relative, 'channel manifest', 'file');
  const bytes = readNoFollow(file.absolute, relative);
  const { privateKey, publicKeyPath, created } = loadOrCreateKeypair(ROOT);
  writeSignature(ROOT, relative, signBytes(privateKey, relative, bytes));
  process.stdout.write(
    `signed ${relative} with ${path.basename(publicKeyPath)}${created ? ' (new keypair created)' : ''}\n`,
  );
}

function commandChannelVerify(relative) {
  assertRelative(relative, 'channel manifest');
  const publicKey = readPublicKey(ROOT);
  const errors = verifySignatureFile(publicKey, relative);
  report([{ label: relative, detail: 'channel manifest signature', errors }]);
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (!command) {
    process.stdout.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  if (MUTATING.has(command) && command !== 'init' && !existsSync(path.join(ROOT, 'opurom.json'))) {
    throw new CliError(`no opurom.json in ${ROOT}; run 'opurom-pkg init <name>' first`);
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
  } else if (command === 'show') {
    commandShow(oneArgument(command, rest));
  } else if (command === 'outdated') {
    noArguments(command, rest);
    commandOutdated();
  } else if (command === 'verify') {
    if (rest.length === 0) {
      commandVerify();
    } else if (rest.length === 1 && rest[0] === '--signed') {
      let lock;
      try {
        lock = readLockData();
      } catch (error) {
        report([{ label: '<lock>', detail: '', errors: [errorText(error)] }]);
        return;
      }
      commandVerifySigned(lock);
    } else {
      throw new CliError(`verify takes no arguments or --signed`, 2);
    }
  } else if (command === 'lock') {
    if (rest.length === 0) {
      commandLock();
    } else if (rest.length === 1 && rest[0] === '--check') {
      commandLockCheck();
    } else {
      throw new CliError('lock takes no arguments or --check', 2);
    }
  } else if (command === 'sign') {
    noArguments(command, rest);
    commandSign();
  } else if (command === 'registry-server') {
    await commandRegistryServer(rest);
  } else if (command === 'github-registry-server') {
    await commandRegistryServer(rest, true);
  } else if (command === 'publish') {
    if (rest[0] === '--github') {
      const { repository, positional } = githubArgs(command, rest, 1);
      await commandPublishGithub(repository, positional[0]);
    } else {
      await commandPublish(oneArgument(command, rest));
    }
  } else if (command === 'install') {
    if (rest[0] === '--github') {
      const { repository, positional } = githubArgs(command, rest, 1);
      await commandInstallGithub(repository, positional[0]);
    } else {
      await commandInstall(oneArgument(command, rest));
    }
  } else if (command === 'update') {
    const sub = rest[0];
    if (sub === 'check') {
      await commandUpdateCheck(rest.slice(1));
    } else if (sub === 'fetch') {
      await commandUpdateFetch(rest.slice(1));
    } else {
      throw new CliError('update needs check or fetch', 2);
    }
  } else if (command === 'channel-sign') {
    commandChannelSign(oneArgument(command, rest));
  } else if (command === 'channel-verify') {
    commandChannelVerify(oneArgument(command, rest));
  } else if (command === 'search') {
    const { repository, positional } = githubArgs(command, rest, [0, 1]);
    await commandSearchGithub(repository, positional);
  } else {
    throw new CliError(`unknown command: ${command}\n${USAGE}`, 2);
  }
}

main(process.argv.slice(2)).catch((error) => {
  if (error instanceof RegistryNetworkError) {
    process.stdout.write(`SKIP network unavailable: ${redactToken(error.reason)}\n`);
    return;
  }
  const code = error instanceof CliError ? error.code : 1;
  const text =
    error instanceof CliError ||
    error instanceof SigningError ||
    error instanceof HttpError ||
    error instanceof GitHubRegistryError ||
    error instanceof ArchiveError
      ? error.message
      : error?.stack ?? String(error);
  process.stderr.write(`error: ${redactToken(text)}\n`);
  process.exitCode = code;
});
