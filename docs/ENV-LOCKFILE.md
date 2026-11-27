# Environment lock files

`melange lock` resolves the build environment of a configuration
(`environment.contents` plus the packages its pipelines need) and writes an
apko lock file:

```shell
melange lock melange.yaml --arch x86_64,aarch64 -o melange.lock.json
```

`melange lock --test` locks the main test environment instead, and takes the
package under test as a second argument, like `melange test`. The file uses
apko's lock format: for each architecture every package's URL, version, APK
checksum, `data.checksum` and `sha256` of the whole `.apk`, the repositories,
and the content of every keyring entry, including the keys discovered for the
repositories. `melange lock` fails when a package from an http(s) repository
gets no `sha256`. `config.checksum` is a digest of the repositories, keyring
and packages the environment asks for (including `--package-append`,
`--keyring-append` and `--repository-append`). An environment that resolves
differently per architecture has to be locked one architecture per file.

`melange lock` verifies the signatures of the repository indexes it resolves
from. `--ignore-signatures` is refused unless `--allow-unverified-lock` is
also given; the lock file then records `"unverified_indexes": true`, builds
from it warn, and builds with `--require-strong-checksums` fail.

## Trust model

The lock file is the trust root of a build from it: the packages are verified
against the checksums it records and the keys are installed from the content
it embeds, so review a lock file like the code it builds. The check that the
lock file matches the configuration (`config.checksum`) detects a stale lock
file, one not regenerated after the configuration changed. It is not a
security boundary: anyone who can edit the lock file can also make it match.

## Building from a lock file

```shell
melange build melange.yaml --env-lockfile melange.lock.json \
  --apk-cache-dir ./apk-cache --offline --require-strong-checksums
```

With `--env-lockfile`, the guest installs exactly the locked packages for its
architecture through apko, which verifies each one against the checksums in
the lock file and installs the keys, including the discovered ones, from their
embedded content, without key discovery. The package list recorded in the
built package is the locked one. The build fails when the lock file was not
generated for the configuration's environment (a package, repository or
keyring entry added, removed or changed, on the command line too), or has no
packages for the architecture.

| Flag | Effect |
| --- | --- |
| `--offline` | Read packages, keys and indexes from `--apk-cache-dir` only. With `--runner qemu`, it needs `QEMU_BASE_INITRAMFS` set to an initramfs built with `melange initramfs`. |
| `--require-strong-checksums` | Fail when a locked package has no `sha256`, a key has no embedded content, or the lock file was written with `--allow-unverified-lock`. |
| `--local-package <name>=sha256:<hex>` | Digest of a package locked with `melange lock --mark-local-packages` from a local repository (`-r`). |

`melange test` takes the same flags. It applies the lock file to the main
test environment, and fails when the configuration has no main test pipeline
or a subpackage has tests.

## Offline cache

An offline build needs, in apko's cache layout under `--apk-cache-dir`, the
raw `.apk` of every locked package. A previous online build from the same
lock file stores them there.

## Repository indexes

Repository indexes are not needed to install from a lock file, but the
package analysis (SCA) that runs after the build uses them to resolve
versioned shared library dependencies. A build from a lock file, online or
offline, never fetches indexes: it reads them from `--apk-cache-dir`, where
`melange lock` with the same cache directory leaves them, and verifies their
signatures with the keys installed from the lock file. An index in the cache
that fails to load, for example on a bad signature, fails the build. When the
index of an http(s) repository is not in the cache, the build has no package
resolver and records no versioned shared library dependencies, with a
warning; with `MELANGE_VERSIONED_SHLIB_DEPENDS` set it fails instead.
