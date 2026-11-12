import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

export const REPO = path.resolve(import.meta.dirname, '..');
export const CLI = path.join(REPO, 'bin', 'opurom-pkg.mjs');
export const REGISTRY = path.join(REPO, 'registry');
export const LOCKFILE = path.join(REPO, 'opurom.lock');

export function makeProject(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'opurom-pkg-test-'));
  cpSync(REGISTRY, path.join(root, 'registry'), { recursive: true });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

export function run(root, ...args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    output: `${result.stdout}${result.stderr}`,
  };
}

export function ok(root, ...args) {
  const result = run(root, ...args);
  assert.equal(result.status, 0, `${args.join(' ')} failed:\n${result.output}`);
  return result;
}

export function readJson(root, relative) {
  return JSON.parse(readFileSync(path.join(root, relative), 'utf8'));
}

export function writeJson(root, relative, value) {
  writeFileSync(path.join(root, relative), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function seededProject(t) {
  const root = makeProject(t);
  writeJson(root, 'opurom.json', {
    name: 'demo-app',
    version: '0.1.0',
    moduleRoots: ['registry'],
    dependencies: {
      'opurom-data': '0.1.0',
      'opurom-ui': '0.1.0',
    },
  });
  ok(root, 'lock');
  return root;
}
