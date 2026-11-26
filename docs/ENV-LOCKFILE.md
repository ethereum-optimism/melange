# Environment lock files

`melange lock` resolves the build environment of a configuration
(`environment.contents` plus the packages its pipelines need) and writes an
apko lock file:

```shell
melange lock melange.yaml --arch x86_64,aarch64 -o melange.lock.json
```

`melange lock --test` locks the main test environment instead. The file uses
apko's lock format: for each architecture every package's URL, version, APK
checksum, `data.checksum` and `sha256` of the whole `.apk`, the repositories,
and the content of every keyring entry. `config.checksum` is a digest of the
repositories, keyring and packages the environment asks for (including
`--package-append`). An environment that resolves differently per
architecture has to be locked one architecture per file.

## Building from a lock file

```shell
melange build melange.yaml --env-lockfile melange.lock.json \
  --apk-cache-dir ./apk-cache --offline --require-strong-checksums
```

With `--env-lockfile`, the guest installs exactly the locked packages for its
architecture through apko, which verifies each one against the checksums in
the lock file and installs the keys from their embedded content. The package
list recorded in the built package is the locked one. The build fails when
the lock file was not generated for the configuration's environment (a
package, repository or keyring entry added, removed or changed), or has no
packages for the architecture.

| Flag | Effect |
| --- | --- |
| `--offline` | Read packages, keys and indexes from `--apk-cache-dir` only. |
| `--require-strong-checksums` | Fail when a locked package has no `sha256` or a key has no embedded content. |
| `--local-package <name>=sha256:<hex>` | Digest of a package locked with `melange lock --mark-local-packages` from a local repository (`-r`). |

`melange test` takes the same flags. It applies the lock file to the main
test environment and fails when a subpackage has tests.

## Offline cache

An offline build needs, in apko's cache layout under `--apk-cache-dir`, the
raw `.apk` of every locked package. A previous online build from the same
lock file stores them there. Repository indexes are not needed to install
from a lock file. Without them the build has no package resolver, which only
matters for versioned shared library dependencies
(`MELANGE_VERSIONED_SHLIB_DEPENDS`): an offline build with that set fails
unless the `APKINDEX` of every repository is in the cache too.
