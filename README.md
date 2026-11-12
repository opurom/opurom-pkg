# opurom-pkg

`opurom-pkg` is a zero-dependency package manager for OPUROM module files. It uses Node v26 builtins only, reads a local `registry/` directory, serves that directory over a loopback mock registry, and can use one GitHub org's Releases as a signed public registry. No npm install is needed.

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
node bin/opurom-pkg.mjs github-registry-server --port 0
node bin/opurom-pkg.mjs search --github opurom/opurom-pkg opurom-ui
node bin/opurom-pkg.mjs publish --github opurom/opurom-pkg opurom-ui@0.1.0
node bin/opurom-pkg.mjs install --github opurom/opurom-pkg opurom-ui@0.1.0
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

## GitHub-backed registry

`--github <owner/repo>` treats one public GitHub repository as a registry. Each exact `name@x.y.z`
version gets tag `opurom-pkg-name-x.y.z` and deterministic assets `opurom-pkg-name-x.y.z.zip` plus
`opurom-pkg-name-x.y.z.zip.sig`. `publish --github` builds a stored ZIP containing the package files
and a SHA-256 manifest, signs the archive bytes and asset name with Ed25519, records the archive
SHA-256 in the Release body, creates or patches the Release, and uploads both assets through the
GitHub REST API using Node's `fetch`. `OPR_GITHUB_TOKEN` is read from the environment only; the token
is never written to a file, log, stdout or tracked artifact.

`search --github <owner/repo> [name]` lists versions only when the archive, detached signature and
SHA-256 Release body are all present. `install --github <owner/repo> <name>@<version>` downloads the
assets over HTTPS, verifies the Ed25519 signature against the locally provisioned `keys/opurom.pub`,
checks the archive SHA-256 against the Release body and every file SHA-256 against the signed ZIP
manifest, then writes files under `registry/`. It rejects tampering, wrong keys, missing signatures,
traversal, unexpected download hosts and bounded-size violations. Public reads do not require a
token; publishing requires one.

`OPUROM_GITHUB_API_URL` accepts only `https://api.github.com` or a loopback HTTP origin.
`github-registry-server --port 0` runs an in-memory GitHub REST subset on an ephemeral loopback port
for offline CI; the same publish/search/install flows use exact versions and no external network.
Publishing without `OPR_GITHUB_TOKEN`, or any GitHub command when the network is unavailable, prints
`SKIP <concrete reason>` and exits 0 without faking a publish. HTTP rejections are reported as
concrete errors with nonzero exit.

### Real API evidence

The authenticated path was exercised once against the `opurom` org:
[release/tag `opurom-pkg-opurom-ui-0.1.0`](https://github.com/opurom/opurom-pkg/releases/tag/opurom-pkg-opurom-ui-0.1.0).
It uploaded `opurom-pkg-opurom-ui-0.1.0.zip` (1048 bytes) and
`opurom-pkg-opurom-ui-0.1.0.zip.sig` (64 bytes); GitHub reported publication at
2026-11-12T22:48:03Z. No token appeared in output and no tracked files changed. No other
repositories were created or deleted.

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
traversal rejection, bounded bodies and port release after shutdown. The R9 tests add GitHub Release
asset naming, mock publish/search/install over real TCP, signature and integrity rejection, wrong-key
and missing-signature rejection, bounded-size and archive traversal rejection, and `SKIP` without a
token or network.

## Honest status and R9+

- One GitHub org's Releases are used as a signed public registry. NO general marketplace service, NO
  ratings and NO mirror network.
- GitHub publish uses a token from `OPR_GITHUB_TOKEN` and HTTPS; public search/install can be
  unauthenticated. The loopback mock is plain HTTP and in-memory only.
- Ed25519 signatures use a local keypair. The publisher public key must be provisioned out of band.
  NO key distribution, rotation or revocation service, NO trust store, NO certificate chain and NO
  publisher identity verification.
- NO code execution; packages are hashed and copied as bytes.
- Exact `x.y.z` versions only; no semver ranges, prerelease tags or transitive dependency graph
  resolution.
- Manifest and lock writes are per-file atomic replacements, not one transaction. `verify` detects
  drift.
- R10+: a key distribution/rotation/revocation service, trust store, ratings, mirror network,
  semver ranges, transitive dependency resolution, transactional writes and a multi-org marketplace
  service.
