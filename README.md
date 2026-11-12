# opurom-pkg

`opurom-pkg` is a zero-dependency package manager for OPUROM module files. It uses Node v26 builtins only, reads a local `registry/` directory and can serve that directory over a loopback mock registry. No npm install is needed.

## Commands

Run each command from the project root:

```sh
node bin/opurom-pkg.mjs init demo-app
node bin/opurom-pkg.mjs add opurom-ui@0.1.0
node bin/opurom-pkg.mjs list
node bin/opurom-pkg.mjs verify
node bin/opurom-pkg.mjs lock
node bin/opurom-pkg.mjs remove opurom-ui
node bin/opurom-pkg.mjs sign
node bin/opurom-pkg.mjs verify --signed
node bin/opurom-pkg.mjs registry-server --port 0
node bin/opurom-pkg.mjs publish opurom-ui@0.1.0
node bin/opurom-pkg.mjs install opurom-ui@0.1.0
```

`init` writes `opurom.json` with `name`, `version`, `moduleRoots` and `dependencies`, plus an empty deterministic `opurom.lock`. `add` resolves one exact `name@x.y.z` package from `registry/<name>/<version>/` and refreshes both the manifest and lock. `remove` refreshes both after deleting a dependency. `lock` regenerates only the lock from the manifest and registry.

Commands run against the current directory. When the current directory has no `opurom.json` and no
`registry/`, the CLI falls back to the package directory that owns the script, so
`node opurom-pkg/bin/opurom-pkg.mjs sign` also works from a parent directory.

## Files

`opurom.json` declares exact local dependency versions:

```json
{
  "name": "opurom-pkg",
  "version": "0.1.0",
  "moduleRoots": ["registry"],
  "dependencies": {
    "opurom-data": "0.1.0",
    "opurom-ui": "0.1.0"
  }
}
```

`opurom.lock` is sorted, deterministic JSON:

```json
{
  "version": 1,
  "packages": [
    {
      "name": "opurom-data",
      "version": "0.1.0",
      "path": "registry/opurom-data/0.1.0",
      "sha256": "...",
      "files": [{ "path": "registry/opurom-data/0.1.0/record.opu", "sha256": "..." }]
    }
  ]
}
```

Each registry package has `opurom-pkg.json` with `name`, `version` and an exact `files` array, plus `.opu` module files. The CLI rejects registry metadata whose file list does not match the directory contents.

## Trust boundary

`verify` reads `opurom.json` and `opurom.lock`, compares manifest dependencies with locked versions, recomputes SHA-256 of every locked file, recomputes each package digest, checks for missing or extra files, and rejects absolute paths, `..` traversal and symlinks. All paths must resolve inside the project root. Any failure prints `FAIL` details and exits nonzero.

`add`, `lock` and `verify` never import or run `.opu` files. They hash bytes only. SHA-256 is an integrity check, not publisher authenticity.

## Signed packages

`sign` generates an Ed25519 keypair under `keys/` (gitignored) if none exists, then writes a detached
signature next to every locked package file and to `opurom.lock`. Each `.sig` covers the relative path
and the file bytes, so renaming a file breaks its signature. `sign` is idempotent: running it twice
reuses the same keypair and rewrites the same signatures.

`verify --signed` checks every locked file and the lockfile against `keys/opurom.pub`. It rejects a
tampered file, a missing signature, a signature made by a different key, and lock drift. `verify`
without `--signed` keeps its R5 behaviour and never looks at signatures.

The private key never leaves the project directory and is never printed. Nothing in this repository
publishes a public key, so `verify --signed` proves only that the files match the local keypair, not
that a trusted publisher produced them.

## Local registry

`registry-server` serves `registry/` over loopback HTTP. `publish <name>@<version>` uploads a local
package with its SHA-256 digest; `install <name>@<version>` downloads an exact version, verifies the
digest, writes it under `registry/` and refreshes the manifest and lock.

```sh
node bin/opurom-pkg.mjs registry-server --port 0
OPUROM_REGISTRY_URL=http://127.0.0.1:4873 node bin/opurom-pkg.mjs publish opurom-ui@0.1.0
OPUROM_REGISTRY_URL=http://127.0.0.1:4873 node bin/opurom-pkg.mjs install opurom-ui@0.1.0
```

`OPUROM_REGISTRY_URL` defaults to `http://127.0.0.1:4873` and only loopback hosts are accepted. The
server rejects absolute paths, `..` traversal and percent-encoded traversal, bounds request bodies at
4 MiB, and answers `404` for unknown packages. `install` verifies the SHA-256 of every downloaded file
and refuses to write a file whose digest does not match the registry listing.

## Tests

```sh
node --test
node --check bin/*.mjs lib/*.mjs test/*.mjs
```

The suite uses temporary project roots and copies the local registry. It covers manifest validation,
add/list/remove round trip, byte-stable lock regeneration, clean verification, tampered files, missing
files, traversal paths, invalid versions, unknown packages and lock drift. The R6 tests add the
sign/verify round trip, tampered content, a wrong key, a missing signature, registry `GET` and `404`,
a publish/install round trip over real TCP against an ephemeral-port server, integrity mismatches,
traversal rejection, bounded bodies and port release after shutdown.

## Honest status and R6+

- Offline local registry plus a loopback mock registry server. NOT a public marketplace.
- The registry speaks plain HTTP on loopback only. NO TLS, NO authentication, NO remote hosts.
- Ed25519 signatures with a local keypair. NO key distribution, NO rotation, NO revocation, NO
  certificate chain, NO trust store. A local public key proves only local keypair consistency.
- NO code execution; packages are hashed and copied as bytes.
- Exact `x.y.z` versions only; no semver ranges, prerelease tags or transitive dependency graph resolution.
- Manifest and lock writes are per-file atomic replacements, not one transaction. `verify` detects drift. A transactional writer, a remote marketplace and publisher identity trust are R7+.
- TLS, a public package marketplace, key distribution, rotation and revocation remain R7+.
