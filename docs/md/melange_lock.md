---
title: "melange lock"
slug: melange_lock
url: /docs/md/melange_lock.md
draft: false
images: []
type: "article"
toc: true
---
## melange lock

Lock the build or test environment of a YAML configuration file

### Synopsis

Resolve the build environment of a configuration (or its main test
environment with --test) for each architecture and write an apko lock file
with every package's URL, version and checksums, including the sha256 of the
whole .apk, and the content of the keyring. Pass the file to melange build
--env-lockfile (melange test --env-lockfile with --test) to install exactly
these packages.

```
melange lock [flags]
```

### Examples

```
  melange lock melange.yaml --arch x86_64,aarch64 -o melange.lock.json
```

### Options

```
      --apk-cache-dir string               directory used for cached apk packages (default is system-defined cache directory)
      --arch strings                       architectures to lock (e.g., x86_64,aarch64) -- default is all, unless specified in config
      --build-option strings               build options to enable
      --env-file strings                   files to use for preloaded environment variables
  -h, --help[=true|false]                  help for lock
      --ignore-signatures[=true|false]     ignore repository signature verification
  -k, --keyring-append strings             path to extra keys to include in the environment keyring
      --mark-local-packages[=true|false]   record packages from local (non-http) repositories as local entries; builds then need --local-package digests for them
  -o, --output string                      path of the lock file to write (default <config>.lock.json)
      --package-append strings             extra packages to install in the environment (as passed to melange build --package-append, or melange test --test-package-append with --test)
      --pipeline-dirs strings              directories used to extend defined built-in pipelines
  -r, --repository-append strings          path to extra repositories to include in the environment
      --test[=true|false]                  lock the main test environment instead of the build environment
      --vars-file string                   file to use for preloaded build configuration variables
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

