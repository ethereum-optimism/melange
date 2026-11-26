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

package build

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"github.com/chainguard-dev/clog"
)

// GuestEnvironment controls how the packages of a build or test guest
// environment are installed.
type GuestEnvironment struct {
	// LockFile is an environment lock file written by `melange lock`. When
	// set, the guest installs exactly the locked packages, verified against
	// the checksums in the lock file, instead of resolving them from the
	// repository indexes.
	LockFile string
	// Offline forbids network access for the guest packages, keys and
	// indexes: they are read from the apk cache directory only.
	Offline bool
	// RequireStrongChecksums fails the guest when a locked package has no
	// whole-file sha256 or a key has no content embedded in the lock file.
	RequireStrongChecksums bool
	// LocalPackages are "<name>=sha256:<hex>" digests for the local entries of
	// the lock file.
	LocalPackages []string
}

func (g GuestEnvironment) validate() error {
	if g.LockFile != "" {
		return nil
	}
	if g.RequireStrongChecksums {
		return errors.New("--require-strong-checksums needs --env-lockfile")
	}
	if len(g.LocalPackages) > 0 {
		return errors.New("--local-package needs --env-lockfile")
	}
	return nil
}

// apkoOptions returns the apko options that install the guest from the lock
// file. They must not be passed to apko's live resolution.
func (g GuestEnvironment) apkoOptions() []apko_build.Option {
	if g.LockFile == "" {
		return nil
	}
	return []apko_build.Option{
		apko_build.WithLockFile(g.LockFile),
		apko_build.WithRequireStrongChecksums(g.RequireStrongChecksums),
		apko_build.WithLocalPackages(g.LocalPackages),
	}
}

// envRequest is what an environment lock is resolved from: the repositories,
// keyring and packages a guest environment asks for.
type envRequest struct {
	Repositories            []string `json:"repositories"`
	BuildRepositories       []string `json:"buildRepositories"`
	RuntimeOnlyRepositories []string `json:"runtimeOnlyRepositories"`
	Keyring                 []string `json:"keyring"`
	Packages                []string `json:"packages"`
}

func sortedSet(lists ...[]string) []string {
	out := []string{}
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func newEnvRequest(ic apko_types.ImageConfiguration, extraPackages []string) envRequest {
	return envRequest{
		Repositories:            sortedSet(ic.Contents.Repositories),
		BuildRepositories:       sortedSet(ic.Contents.BuildRepositories),
		RuntimeOnlyRepositories: sortedSet(ic.Contents.RuntimeOnlyRepositories),
		Keyring:                 sortedSet(ic.Contents.Keyring),
		Packages:                sortedSet(ic.Contents.Packages, extraPackages),
	}
}

func (r envRequest) checksum() string {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// envToLock is one architecture's guest environment to resolve into a lock.
type envToLock struct {
	arch          apko_types.Architecture
	ic            apko_types.ImageConfiguration
	extraPackages []string
	apkoOpts      []apko_build.Option
}

// generateEnvLock resolves envs through apko and returns one lock file
// covering every architecture. The lock records the checksum of the
// environment request, so a build can detect a lock that no longer matches
// its configuration.
func generateEnvLock(ctx context.Context, name string, envs []envToLock) (*lock.Lock, error) {
	if len(envs) == 0 {
		return nil, errors.New("no architecture to lock")
	}
	sum := newEnvRequest(envs[0].ic, envs[0].extraPackages).checksum()
	for _, e := range envs[1:] {
		if newEnvRequest(e.ic, e.extraPackages).checksum() != sum {
			return nil, fmt.Errorf("the environment for %s differs from the one for %s: lock each architecture to its own file with --arch", e.arch.ToAPK(), envs[0].arch.ToAPK())
		}
	}

	out := &lock.Lock{
		Version: "v1",
		Config:  &lock.Config{Name: name, DeepChecksum: sum},
		Contents: lock.LockContents{
			Packages:                []lock.LockPkg{},
			BuildRepositories:       []lock.LockRepo{},
			RuntimeOnlyRepositories: []lock.LockRepo{},
			Repositories:            []lock.LockRepo{},
			Keyrings:                []lock.LockKeyring{},
		},
	}
	keyrings := map[string]lock.LockKeyring{}
	for _, e := range envs {
		ic := e.ic
		ic.Archs = []apko_types.Architecture{e.arch}
		opts := append(slices.Clone(e.apkoOpts), apko_build.WithImageConfiguration(ic))
		l, err := apko_build.GenerateLock(ctx, []apko_types.Architecture{e.arch}, opts)
		if err != nil {
			return nil, fmt.Errorf("locking the %s environment: %w", e.arch.ToAPK(), err)
		}
		out.Contents.Packages = append(out.Contents.Packages, l.Contents.Packages...)
		out.Contents.BuildRepositories = append(out.Contents.BuildRepositories, l.Contents.BuildRepositories...)
		out.Contents.RuntimeOnlyRepositories = append(out.Contents.RuntimeOnlyRepositories, l.Contents.RuntimeOnlyRepositories...)
		out.Contents.Repositories = append(out.Contents.Repositories, l.Contents.Repositories...)
		for _, k := range l.Contents.Keyrings {
			if prev, ok := keyrings[k.Name]; ok && prev.Content != k.Content {
				return nil, fmt.Errorf("keyring entry %s resolved to different content for different architectures", k.Name)
			}
			keyrings[k.Name] = k
		}
	}
	for _, k := range keyrings {
		out.Contents.Keyrings = append(out.Contents.Keyrings, k)
	}
	sort.Slice(out.Contents.Keyrings, func(i, j int) bool {
		return out.Contents.Keyrings[i].Name < out.Contents.Keyrings[j].Name
	})
	return out, nil
}

// packageName returns the package name of a world entry such as "foo",
// "foo=1.2-r0" or "foo>=1.2".
func packageName(entry string) string {
	if i := strings.IndexAny(entry, "=<>~"); i >= 0 {
		return entry[:i]
	}
	return entry
}

// lockedEnvironment loads the lock file, checks that it was generated for the
// environment ic asks for, and returns ic with its packages pinned to the
// versions locked for arch.
func lockedEnvironment(file string, ic apko_types.ImageConfiguration, extraPackages []string, arch apko_types.Architecture) (apko_types.ImageConfiguration, error) {
	l, err := lock.FromFile(file)
	if err != nil {
		return ic, fmt.Errorf("loading environment lock file: %w", err)
	}
	if err := verifyEnvLock(file, l, ic, extraPackages, arch); err != nil {
		return ic, err
	}

	pinned := []string{}
	for _, p := range l.Contents.Packages {
		if p.Architecture == arch.ToAPK() {
			pinned = append(pinned, p.Name+"="+p.Version)
		}
	}
	slices.Sort(pinned)
	ic.Contents.Packages = pinned
	ic.Archs = []apko_types.Architecture{arch}
	return ic, nil
}

// verifyEnvLock fails when l was not generated for the environment that ic
// and extraPackages ask for, or has no packages for arch.
func verifyEnvLock(file string, l lock.Lock, ic apko_types.ImageConfiguration, extraPackages []string, arch apko_types.Architecture) error {
	if l.Config == nil || l.Config.DeepChecksum == "" {
		return fmt.Errorf("environment lock file %s records no environment checksum: generate it with melange lock", file)
	}
	req := newEnvRequest(ic, extraPackages)
	if l.Config.DeepChecksum != req.checksum() {
		return fmt.Errorf("environment lock file %s does not match the %s environment of the configuration (regenerate it with melange lock)%s", file, arch.ToAPK(), envLockMismatch(l, req, arch))
	}
	for _, p := range l.Contents.Packages {
		if p.Architecture == arch.ToAPK() {
			return nil
		}
	}
	return fmt.Errorf("environment lock file %s has no packages for %s", file, arch.ToAPK())
}

// envLockMismatch describes the differences between the lock and req that
// can be seen from the lock contents: requested packages that are not
// locked, and repositories that differ.
func envLockMismatch(l lock.Lock, req envRequest, arch apko_types.Architecture) string {
	locked := map[string]bool{}
	for _, p := range l.Contents.Packages {
		if p.Architecture == arch.ToAPK() {
			locked[p.Name] = true
		}
	}
	missing := []string{}
	for _, p := range req.Packages {
		if n := packageName(p); !locked[n] && !strings.Contains(n, ":") {
			missing = append(missing, p)
		}
	}

	lockedRepos := []string{}
	suffix := "/" + arch.ToAPK()
	for _, repos := range [][]lock.LockRepo{l.Contents.Repositories, l.Contents.BuildRepositories, l.Contents.RuntimeOnlyRepositories} {
		for _, r := range repos {
			if r.Architecture == arch.ToAPK() {
				lockedRepos = append(lockedRepos, strings.TrimSuffix(r.Name, suffix))
			}
		}
	}
	wantRepos := []string{}
	for _, r := range sortedSet(req.Repositories, req.BuildRepositories, req.RuntimeOnlyRepositories) {
		name, err := apko_build.RemoveRepositoryLabel(r)
		if err != nil {
			name = r
		}
		wantRepos = append(wantRepos, strings.TrimPrefix(strings.TrimPrefix(name, "https://"), "http://"))
	}

	var details []string
	if len(missing) > 0 {
		details = append(details, "requested packages not in the lock: "+strings.Join(missing, ", "))
	}
	if lr := sortedSet(lockedRepos); !slices.Equal(lr, sortedSet(wantRepos)) {
		details = append(details, fmt.Sprintf("repositories: lock has %v, configuration has %v", lr, sortedSet(wantRepos)))
	}
	if len(details) == 0 {
		return ""
	}
	return ": " + strings.Join(details, "; ")
}

// guestPkgResolver returns the package resolver for the guest's repository
// indexes. An offline guest installed from a lock file does not need the
// indexes, so when some are not in the apk cache it returns a nil resolver,
// which skips versioned shared library dependencies, unless those were
// requested with MELANGE_VERSIONED_SHLIB_DEPENDS.
func guestPkgResolver(ctx context.Context, g GuestEnvironment, bc *apko_build.Context) (*apk.PkgResolver, error) {
	namedIndexes, err := bc.APK().GetRepositoryIndexes(ctx, false)
	if g.LockFile == "" || !g.Offline {
		if err != nil {
			return nil, fmt.Errorf("unable to obtain repository indexes: %w", err)
		}
		return apk.NewPkgResolver(ctx, namedIndexes), nil
	}

	if err == nil {
		repos, rerr := bc.APK().GetRepositories()
		if rerr != nil {
			return nil, fmt.Errorf("unable to list repositories: %w", rerr)
		}
		remote := 0
		for _, r := range repos {
			if strings.Contains(r, "://") {
				remote++
			}
		}
		if len(namedIndexes) >= remote {
			return apk.NewPkgResolver(ctx, namedIndexes), nil
		}
		err = fmt.Errorf("%d of %d remote repository indexes are in the apk cache", len(namedIndexes), remote)
	}
	if os.Getenv("MELANGE_VERSIONED_SHLIB_DEPENDS") != "" {
		return nil, fmt.Errorf("versioned shared library dependencies need the APKINDEX of every repository in the apk cache when building offline from a lock file: %w", err)
	}
	clog.FromContext(ctx).Warnf("repository indexes are missing from the apk cache (%v); building without a package resolver, so no versioned shared library dependencies", err)
	return nil, nil
}

// LockOptions controls how `melange lock` resolves an environment.
type LockOptions struct {
	// MarkLocalPackages records packages from local (non-http) repositories
	// as local entries, whose digests are supplied with --local-package at
	// build time.
	MarkLocalPackages bool
}

// LockBuildEnvironment compiles the configuration for each of archs and
// resolves its build guest environment into one lock file.
func LockBuildEnvironment(ctx context.Context, archs []apko_types.Architecture, lo LockOptions, opts ...Option) (*lock.Lock, error) {
	log := clog.FromContext(ctx)
	var (
		envs []envToLock
		name string
	)
	for _, arch := range archs {
		b, err := New(ctx, append(slices.Clone(opts), WithArch(arch))...)
		if errors.Is(err, ErrSkipThisArch) {
			log.Warnf("skipping arch %s", arch.ToAPK())
			continue
		} else if err != nil {
			return nil, err
		}
		if err := b.Compile(ctx); err != nil {
			return nil, fmt.Errorf("compiling %s: %w", b.ConfigFile, err)
		}
		name = b.ConfigFile
		envs = append(envs, envToLock{
			arch:          arch,
			ic:            b.Configuration.Environment,
			extraPackages: b.ExtraPackages,
			apkoOpts:      append(b.guestApkoOptions(""), apko_build.WithMarkLocalPackages(lo.MarkLocalPackages)),
		})
	}
	return generateEnvLock(ctx, name, envs)
}

// LockTestEnvironment compiles the configuration for each of archs and
// resolves its main test guest environment into one lock file.
func LockTestEnvironment(ctx context.Context, archs []apko_types.Architecture, lo LockOptions, opts ...TestOption) (*lock.Lock, error) {
	var (
		envs []envToLock
		name string
	)
	for _, arch := range archs {
		t, err := NewTest(ctx, append(slices.Clone(opts), WithTestArch(arch))...)
		if err != nil {
			return nil, err
		}
		if err := t.Compile(ctx); err != nil {
			return nil, fmt.Errorf("compiling %s tests: %w", t.ConfigFile, err)
		}
		if t.IsTestless() {
			return nil, fmt.Errorf("%s has no main test pipeline to lock an environment for", t.ConfigFile)
		}
		name = t.ConfigFile
		envs = append(envs, envToLock{
			arch:          arch,
			ic:            t.Configuration.Test.Environment,
			extraPackages: t.ExtraTestPackages,
			apkoOpts:      append(t.guestApkoOptions(""), apko_build.WithMarkLocalPackages(lo.MarkLocalPackages)),
		})
	}
	return generateEnvLock(ctx, name, envs)
}
