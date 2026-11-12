import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
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

// Starts a real registry server on an ephemeral loopback port.
export async function spawnRegistry(root) {
  const child = spawn(process.execPath, [CLI, 'registry-server', '--port', '0'], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString('utf8');
  });
  const port = await new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(
      () => reject(new Error(`registry server did not start:\n${stderr}`)),
      10000,
    );
    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const match = /http:\/\/127\.0\.0\.1:(\d+)/.exec(buffer);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`registry server exited with ${code}:\n${stderr}`));
    });
  });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve();
      }, 5000);
      child.on('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  };
  return { child, port, url: `http://127.0.0.1:${port}`, stop };
}

// Starts a real registry server on an ephemeral loopback port and stops it afterwards.
export async function startRegistry(t, root) {
  const server = await spawnRegistry(root);
  t.after(() => server.stop());
  return server;
}

export function runWithEnv(root, env, ...args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    output: `${result.stdout}${result.stderr}`,
  };
}

// Async variant: a registry server in this process cannot answer a spawnSync child.
export function runWithEnvAsync(root, env, ...args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (status) => {
      resolve({ status, stdout, stderr, output: `${stdout}${stderr}` });
    });
  });
}
