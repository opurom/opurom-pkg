# opurom-pkg

`opurom-pkg` is a zero-dependency, offline package manager for OPUROM module files. It uses Node v26 builtins only and reads a local `registry/` directory. No npm install is needed.

## Commands

Run each command from the project root:

```sh
node bin/opurom-pkg.mjs init demo-app
node bin/opurom-pkg.mjs add opurom-ui@0.1.0
node bin/opurom-pkg.mjs list
node bin/opurom-pkg.mjs verify
node bin/opurom-pkg.mjs lock
node bin/opurom-pkg.mjs remove opurom-ui
```

`init` writes `opurom.json` with `name`, `version`, `moduleRoots` and `dependencies`, plus an empty deterministic `opurom.lock`. `add` resolves one exact `name@x.y.z` package from `registry/<name>/<version>/` and refreshes both the manifest and lock. `remove` refreshes both after deleting a dependency. `lock` regenerates only the lock from the manifest and registry.

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

## Tests

```sh
node --test
node --check bin/*.mjs lib/*.mjs test/*.mjs
```

The suite uses temporary project roots and copies the local registry. It covers manifest validation, add/list/remove round trip, byte-stable lock regeneration, clean verification, tampered files, missing files, traversal paths, invalid versions, unknown packages and lock drift.

## Honest status and R5+

- Offline local registry only.
- NO remote marketplace.
- NO network resolution.
- NO code execution.
- NO signing or publisher identity; there is no authenticity check.
- Exact `x.y.z` versions only; no semver ranges, prerelease tags or transitive dependency graph resolution.
- Manifest and lock writes are per-file atomic replacements, not one transaction. `verify` detects drift. A transactional writer, remote marketplace, signing and publisher identity are R5+.
- No remote package marketplace is implemented or implied; R5+ work may add it.
