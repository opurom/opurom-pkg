// Ed25519 detached signatures over locked package files. Node builtins only.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as detachedSign,
  verify as detachedVerify,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export const SIG_EXT = '.sig';

export class SigningError extends Error {}

function keyDirectory(root) {
  return path.join(root, 'keys');
}

// The private key never leaves the project directory and is never printed.
export function loadOrCreateKeypair(root) {
  const directory = keyDirectory(root);
  const privatePath = path.join(directory, 'opurom.key');
  const publicPath = path.join(directory, 'opurom.pub');
  if (existsSync(privatePath)) {
    const privateKey = createPrivateKey(readFileSync(privatePath));
    const publicKey = createPublicKey(privateKey);
    return { privateKey, publicKey, publicKeyPath: publicPath, created: false };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  mkdirSync(directory, { recursive: true });
  writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    mode: 0o600,
  });
  writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), {
    mode: 0o644,
  });
  return { privateKey, publicKey, publicKeyPath: publicPath, created: true };
}

export function readPublicKey(root) {
  const publicPath = path.join(root, 'keys', 'opurom.pub');
  if (!existsSync(publicPath)) {
    throw new SigningError(
      `missing public key ${publicPath}; run sign first or provide the publisher public key`,
    );
  }
  return createPublicKey(readFileSync(publicPath));
}

// A signature covers the relative path and the bytes, so renaming a file breaks it.
export function signBytes(privateKey, relativePath, bytes) {
  const payload = Buffer.concat([
    Buffer.from(`${relativePath}\n`, 'utf8'),
    Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes),
  ]);
  return detachedSign(null, payload, privateKey);
}

export function verifyBytes(publicKey, relativePath, bytes, signature) {
  const payload = Buffer.concat([
    Buffer.from(`${relativePath}\n`, 'utf8'),
    Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes),
  ]);
  return detachedVerify(null, payload, publicKey, signature);
}

export function writeSignature(root, relativePath, signature) {
  const target = path.join(root, `${relativePath}${SIG_EXT}`);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, signature);
  return target;
}

export function readSignature(root, relativePath) {
  const target = path.join(root, `${relativePath}${SIG_EXT}`);
  if (!existsSync(target)) return null;
  return readFileSync(target);
}
