// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"chainguard.dev/melange/pkg/build"
)

// GuestFlags are the flags that install a guest environment from an
// environment lock file.
type GuestFlags struct {
	EnvLockfile            string
	Offline                bool
	RequireStrongChecksums bool
	LocalPackages          []string
}

func addGuestFlags(fs *pflag.FlagSet, flags *GuestFlags, kind string) {
	lockCmd := "melange lock"
	if kind == "test" {
		lockCmd = "melange lock --test"
	}
	fs.StringVar(&flags.EnvLockfile, "env-lockfile", "", fmt.Sprintf("install the %s environment from this lock file (written by %s) instead of resolving it from the repository indexes", kind, lockCmd))
	fs.BoolVar(&flags.Offline, "offline", false, fmt.Sprintf("read the %s environment packages, keys and indexes from --apk-cache-dir only, without network access", kind))
	fs.BoolVar(&flags.RequireStrongChecksums, "require-strong-checksums", false, "fail when the environment lock file has a package without a sha256 or a key without embedded content, or was resolved from unverified repository indexes")
	fs.StringArrayVar(&flags.LocalPackages, "local-package", nil, "<name>=sha256:<hex> digest of a local package of the environment lock file (repeatable)")
}

type lockFlags struct {
	archstrs     []string
	output       string
	test         bool
	markLocal    bool
	pipelineDirs []string
	extraKeys    []string
	extraRepos   []string
	extraPkgs    []string
	apkCacheDir  string
	envFiles     []string
	varsFile     string
	buildOptions []string
	ignoreSigs   bool
	allowUnverif bool
}

func lockCmd() *cobra.Command {
	flags := &lockFlags{}

	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock the build or test environment of a YAML configuration file",
		Long: `Resolve the build environment of a configuration (or its main test
environment with --test) for each architecture and write an apko lock file
with every package's URL, version and checksums, including the sha256 of the
whole .apk, and the content of the keyring. Pass the file to melange build
--env-lockfile (melange test --env-lockfile with --test) to install exactly
these packages.`,
		Example: `  melange lock melange.yaml --arch x86_64,aarch64 -o melange.lock.json
  melange lock --test melange.yaml mypackage --arch x86_64 -o melange.test.lock.json`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLock(cmd.Context(), flags, args)
		},
	}

	fs := cmd.Flags()
	fs.StringSliceVar(&flags.archstrs, "arch", nil, "architectures to lock (e.g., x86_64,aarch64) -- default is all, unless specified in config")
	fs.StringVarP(&flags.output, "output", "o", "", "path of the lock file to write (default <config>.lock.json)")
	fs.BoolVar(&flags.test, "test", false, "lock the main test environment instead of the build environment")
	fs.BoolVar(&flags.markLocal, "mark-local-packages", false, "record packages from local (non-http) repositories as local entries; builds then need --local-package digests for them")
	fs.StringSliceVar(&flags.pipelineDirs, "pipeline-dirs", []string{}, "directories used to extend defined built-in pipelines")
	fs.StringSliceVarP(&flags.extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the environment keyring")
	fs.StringSliceVarP(&flags.extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the environment")
	fs.StringSliceVar(&flags.extraPkgs, "package-append", []string{}, "extra packages to install in the environment (as passed to melange build --package-append, or melange test --test-package-append with --test)")
	fs.StringVar(&flags.apkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringSliceVar(&flags.envFiles, "env-file", []string{}, "files to use for preloaded environment variables")
	fs.StringVar(&flags.varsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	fs.StringSliceVar(&flags.buildOptions, "build-option", []string{}, "build options to enable")
	fs.BoolVar(&flags.ignoreSigs, "ignore-signatures", false, "ignore repository signature verification (needs --allow-unverified-lock)")
	fs.BoolVar(&flags.allowUnverif, "allow-unverified-lock", false, "with --ignore-signatures, write a lock file marked as resolved from unverified indexes, which builds with --require-strong-checksums reject")

	return cmd
}

func runLock(ctx context.Context, flags *lockFlags, args []string) error {
	log := clog.FromContext(ctx)
	configFile := args[0]

	if flags.ignoreSigs && !flags.allowUnverif {
		return fmt.Errorf("--ignore-signatures writes a lock file resolved from unverified repository indexes; pass --allow-unverified-lock to write one anyway")
	}
	if flags.allowUnverif && !flags.ignoreSigs {
		return fmt.Errorf("--allow-unverified-lock needs --ignore-signatures")
	}
	if len(args) > 1 && !flags.test {
		return fmt.Errorf("a package name argument is only accepted with --test")
	}

	archs := apko_types.ParseArchitectures(flags.archstrs)
	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}
	output := flags.output
	if output == "" {
		output = strings.TrimSuffix(configFile, filepath.Ext(configFile)) + ".lock.json"
	}
	pipelineDirs := append(append([]string{}, flags.pipelineDirs...), BuiltinPipelineDir)
	lo := build.LockOptions{MarkLocalPackages: flags.markLocal}

	if flags.test {
		if flags.varsFile != "" || len(flags.buildOptions) > 0 {
			return fmt.Errorf("--vars-file and --build-option apply to the build environment, not with --test")
		}
		opts := []build.TestOption{
			build.WithTestConfig(configFile),
			build.WithTestExtraKeys(flags.extraKeys),
			build.WithTestExtraRepos(flags.extraRepos),
			build.WithExtraTestPackages(flags.extraPkgs),
			build.WithTestPackageCacheDir(flags.apkCacheDir),
			build.WithTestEnvFiles(flags.envFiles),
			build.WithTestIgnoreSignatures(flags.ignoreSigs),
		}
		if len(args) > 1 {
			opts = append(opts, build.WithTestPackage(args[1]))
		}
		for _, d := range pipelineDirs {
			opts = append(opts, build.WithTestPipelineDir(d))
		}
		l, err := build.LockTestEnvironment(ctx, archs, lo, opts...)
		if err != nil {
			return err
		}
		log.Infof("writing %s", output)
		return l.SaveToFile(output)
	}

	commit, err := detectGitHead(ctx, configFile)
	if err != nil {
		log.Warnf("unable to detect commit for build config file: %v", err)
		commit = "unknown"
	}
	opts := []build.Option{
		build.WithConfig(configFile),
		build.WithConfigFileRepositoryCommit(commit),
		build.WithConfigFileRepositoryURL("https://unknown/unknown/unknown"),
		build.WithExtraKeys(flags.extraKeys),
		build.WithExtraRepos(flags.extraRepos),
		build.WithExtraPackages(flags.extraPkgs),
		build.WithPackageCacheDir(flags.apkCacheDir),
		build.WithEnvFiles(flags.envFiles),
		build.WithVarsFile(flags.varsFile),
		build.WithEnabledBuildOptions(flags.buildOptions),
		build.WithIgnoreSignatures(flags.ignoreSigs),
	}
	for _, d := range pipelineDirs {
		opts = append(opts, build.WithPipelineDir(d))
	}
	l, err := build.LockBuildEnvironment(ctx, archs, lo, opts...)
	if err != nil {
		return err
	}
	log.Infof("writing %s", output)
	return l.SaveToFile(output)
}
