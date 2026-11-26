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
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

type countingTransport struct {
	next  http.RoundTripper
	count atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return c.next.RoundTrip(r)
}

// countNetwork counts every request made through http.DefaultTransport and
// through clients that use it, for the rest of the test.
func countNetwork(t *testing.T) *countingTransport {
	t.Helper()
	ct := &countingTransport{next: http.DefaultTransport}
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = ct.next })
	return ct
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, os.CopyFS(dst, os.DirFS(src)))
	return dst
}

func findFiles(t *testing.T, root string, match func(name string) bool) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && match(d.Name()) {
			out = append(out, p)
		}
		return nil
	}))
	return out
}

type envLockFixture struct {
	ic       apko_types.ImageConfiguration
	lockFile string
	// cache holds the locked packages and keys, but no repository index.
	cache string
	// served counts the requests the package repository received.
	served *atomic.Int64
}

// newEnvLockFixture locks a test environment against a local HTTP package
// repository, installs it once online to fill an apk cache, and then shuts
// the repository down.
func newEnvLockFixture(t *testing.T) envLockFixture {
	t.Helper()
	ctx := context.Background()

	served := &atomic.Int64{}
	files := http.FileServer(http.Dir(filepath.Join("testdata", "envlock")))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		files.ServeHTTP(w, r)
	}))

	ic := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Repositories: []string{srv.URL},
			Keyring:      []string{srv.URL + "/melange.rsa.pub"},
			Packages:     []string{"replayout"},
		},
	}
	cache := t.TempDir()
	b := &Build{Arch: apko_types.ParseArchitecture("x86_64"), ApkCacheDir: cache, Configuration: &config.Configuration{}}

	l, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: b.Arch, ic: ic, apkoOpts: b.guestApkoOptions("")}})
	require.NoError(t, err)
	lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))

	b.Guest = GuestEnvironment{LockFile: lockFile}
	bc, err := b.newGuestContext(ctx, ic, tarfs.New(), t.TempDir())
	require.NoError(t, err)
	require.NoError(t, bc.BuildImage(ctx))
	require.NotZero(t, served.Load())

	srv.Close()
	for _, p := range findFiles(t, cache, func(n string) bool { return strings.HasPrefix(n, "APKINDEX") }) {
		require.NoError(t, os.Remove(p))
	}
	require.NotEmpty(t, findFiles(t, cache, func(n string) bool { return strings.HasSuffix(n, ".apk") }))

	return envLockFixture{ic: ic, lockFile: lockFile, cache: cache, served: served}
}

func TestEnvLockOfflineInstall(t *testing.T) {
	fx := newEnvLockFixture(t)

	tests := []struct {
		name string
		// packages replaces the requested packages when set.
		packages []string
		guest    GuestEnvironment
		// prepare edits the copy of the cache and the lock file.
		prepare func(t *testing.T, cache, lockFile string)
		env     map[string]string
		wantErr string
	}{
		{
			name:  "installs from the cache with zero network",
			guest: GuestEnvironment{Offline: true, RequireStrongChecksums: true},
		},
		{
			name:  "corrupted cached package fails",
			guest: GuestEnvironment{Offline: true},
			prepare: func(t *testing.T, cache, _ string) {
				for _, p := range findFiles(t, cache, func(n string) bool { return strings.HasSuffix(n, ".apk") }) {
					f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
					require.NoError(t, err)
					_, err = f.Write([]byte("tampered"))
					require.NoError(t, err)
					require.NoError(t, f.Close())
				}
			},
			wantErr: "expanding",
		},
		{
			name:  "cached package replaced by another valid package fails",
			guest: GuestEnvironment{Offline: true},
			prepare: func(t *testing.T, cache, _ string) {
				other, err := os.ReadFile(filepath.Join("testdata", "envlock", "x86_64", "custom-ca-certs-2-1.0.0-r0.apk"))
				require.NoError(t, err)
				for _, p := range findFiles(t, cache, func(n string) bool { return strings.HasSuffix(n, ".apk") }) {
					require.NoError(t, os.WriteFile(p, other, 0o644))
				}
			},
			wantErr: "hash mismatch",
		},
		{
			name:     "lock that does not match the configuration fails",
			packages: []string{"replayout", "custom-ca-certs-1"},
			guest:    GuestEnvironment{Offline: true},
			wantErr:  "requested packages not in the lock: custom-ca-certs-1",
		},
		{
			name:  "missing strong checksum fails with require-strong-checksums",
			guest: GuestEnvironment{Offline: true, RequireStrongChecksums: true},
			prepare: func(t *testing.T, _, lockFile string) {
				l, err := lock.FromFile(lockFile)
				require.NoError(t, err)
				for i := range l.Contents.Packages {
					l.Contents.Packages[i].SHA256 = ""
				}
				require.NoError(t, l.SaveToFile(lockFile))
			},
			wantErr: "sha256",
		},
		{
			name:    "versioned shlib depends need the repository index offline",
			guest:   GuestEnvironment{Offline: true},
			env:     map[string]string{"MELANGE_VERSIONED_SHLIB_DEPENDS": "1"},
			wantErr: "versioned shared library dependencies need the APKINDEX",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			cache := copyDir(t, fx.cache)
			lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
			data, err := os.ReadFile(fx.lockFile)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(lockFile, data, 0o644))
			if tt.prepare != nil {
				tt.prepare(t, cache, lockFile)
			}

			ic := fx.ic
			if tt.packages != nil {
				ic.Contents.Packages = tt.packages
			}
			guest := tt.guest
			guest.LockFile = lockFile
			b := &Build{Arch: apko_types.ParseArchitecture("x86_64"), ApkCacheDir: cache, Guest: guest, Configuration: &config.Configuration{}}

			net := countNetwork(t)
			served := fx.served.Load()
			err = func() error {
				bc, err := b.newGuestContext(ctx, ic, tarfs.New(), t.TempDir())
				if err != nil {
					return err
				}
				if err := bc.BuildImage(ctx); err != nil {
					return fmt.Errorf("unable to generate image: %w", err)
				}
				return nil
			}()
			require.Zero(t, net.count.Load(), "offline guest made network requests")
			require.Equal(t, served, fx.served.Load())

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Nil(t, b.PkgResolver)
			require.Equal(t, []string{"pretend-baselayout=1.0.0-r0", "replayout=1.0.0-r0"}, b.Configuration.Environment.Contents.Packages)
		})
	}
}

func TestGuestEnvironmentValidate(t *testing.T) {
	tests := []struct {
		name    string
		guest   GuestEnvironment
		wantErr string
	}{
		{name: "empty"},
		{name: "offline without lock file", guest: GuestEnvironment{Offline: true}},
		{name: "lock file with all options", guest: GuestEnvironment{LockFile: "x", Offline: true, RequireStrongChecksums: true, LocalPackages: []string{"a=sha256:00"}}},
		{name: "strong checksums without lock file", guest: GuestEnvironment{RequireStrongChecksums: true}, wantErr: "--require-strong-checksums needs --env-lockfile"},
		{name: "local package without lock file", guest: GuestEnvironment{LocalPackages: []string{"a=sha256:00"}}, wantErr: "--local-package needs --env-lockfile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.guest.validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVerifyEnvLock(t *testing.T) {
	x86 := apko_types.ParseArchitecture("x86_64")
	ic := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Repositories: []string{"https://packages.example/os"},
			Keyring:      []string{"https://packages.example/key.rsa.pub"},
			Packages:     []string{"busybox", "make>=4"},
		},
	}
	good := lock.Lock{
		Version: "v1",
		Config:  &lock.Config{Name: "melange.yaml", DeepChecksum: newEnvRequest(ic, []string{"git"}).checksum()},
		Contents: lock.LockContents{
			Repositories: []lock.LockRepo{{Name: "packages.example/os/x86_64", Architecture: "x86_64"}},
			Packages: []lock.LockPkg{
				{Name: "busybox", Version: "1.37.0-r0", Architecture: "x86_64"},
				{Name: "make", Version: "4.4-r0", Architecture: "x86_64"},
				{Name: "git", Version: "2.50.0-r0", Architecture: "x86_64"},
			},
		},
	}
	withPackages := func(pkgs ...string) apko_types.ImageConfiguration {
		c := ic
		c.Contents.Packages = pkgs
		return c
	}
	withRepos := func(repos ...string) apko_types.ImageConfiguration {
		c := ic
		c.Contents.Repositories = repos
		return c
	}

	tests := []struct {
		name    string
		lock    lock.Lock
		ic      apko_types.ImageConfiguration
		extra   []string
		arch    apko_types.Architecture
		wantErr string
	}{
		{name: "matching", lock: good, ic: ic, extra: []string{"git"}, arch: x86},
		{name: "package order and duplicates do not matter", lock: good, ic: withPackages("make>=4", "busybox", "busybox"), extra: []string{"git"}, arch: x86},
		{name: "no checksum", lock: lock.Lock{Version: "v1"}, ic: ic, arch: x86, wantErr: "records no environment checksum"},
		{name: "added package", lock: good, ic: withPackages("busybox", "make>=4", "curl"), extra: []string{"git"}, arch: x86, wantErr: "requested packages not in the lock: curl"},
		{name: "removed package", lock: good, ic: withPackages("busybox"), extra: []string{"git"}, arch: x86, wantErr: "does not match the x86_64 environment"},
		{name: "changed version constraint", lock: good, ic: withPackages("busybox", "make>=5"), extra: []string{"git"}, arch: x86, wantErr: "does not match"},
		{name: "extra package not passed", lock: good, ic: ic, arch: x86, wantErr: "does not match"},
		{name: "changed repository", lock: good, ic: withRepos("https://other.example/os"), extra: []string{"git"}, arch: x86, wantErr: "repositories: lock has [packages.example/os], configuration has [other.example/os]"},
		{name: "no packages for arch", lock: good, ic: ic, extra: []string{"git"}, arch: apko_types.ParseArchitecture("aarch64"), wantErr: "has no packages for aarch64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyEnvLock("melange.lock.json", tt.lock, tt.ic, tt.extra, tt.arch)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGenerateEnvLockRejectsDivergentArchitectures(t *testing.T) {
	a := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{Packages: []string{"busybox"}}}
	b := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{Packages: []string{"busybox", "gcc"}}}
	_, err := generateEnvLock(context.Background(), "melange.yaml", []envToLock{
		{arch: apko_types.ParseArchitecture("x86_64"), ic: a},
		{arch: apko_types.ParseArchitecture("aarch64"), ic: b},
	})
	require.ErrorContains(t, err, "the environment for aarch64 differs from the one for x86_64")

	_, err = generateEnvLock(context.Background(), "melange.yaml", nil)
	require.ErrorContains(t, err, "no architecture to lock")
}

func TestPackageName(t *testing.T) {
	for in, want := range map[string]string{
		"busybox":          "busybox",
		"busybox=1.37-r0":  "busybox",
		"make>=4":          "make",
		"gcc~14":           "gcc",
		"glibc<2.40":       "glibc",
		"so:libc.so.6":     "so:libc.so.6",
		"cmd:sh=1.37.0-r0": "cmd:sh",
	} {
		require.Equal(t, want, packageName(in), in)
	}
}

func TestLockBuildEnvironment(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("testdata", "envlock"))))
	defer srv.Close()

	dir := t.TempDir()
	recipe := filepath.Join(dir, "melange.yaml")
	require.NoError(t, os.WriteFile(recipe, []byte(`package:
  name: hello
  version: 1.0.0
  epoch: 0
environment:
  contents:
    repositories:
      - `+srv.URL+`
    keyring:
      - `+srv.URL+`/melange.rsa.pub
    packages:
      - replayout
pipeline:
  - runs: echo hello
`), 0o644))

	archs := []apko_types.Architecture{apko_types.ParseArchitecture("x86_64"), apko_types.ParseArchitecture("aarch64")}
	opts := []Option{
		WithConfig(recipe),
		WithConfigFileRepositoryURL("https://example.com/repo"),
		WithConfigFileRepositoryCommit("deadbeef"),
		WithPackageCacheDir(t.TempDir()),
		WithExtraPackages([]string{"pretend-baselayout"}),
	}
	l, err := LockBuildEnvironment(ctx, archs, LockOptions{}, opts...)
	require.NoError(t, err)

	byArch := map[string][]string{}
	for _, p := range l.Contents.Packages {
		require.NotEmpty(t, p.URL)
		require.True(t, strings.HasPrefix(p.SHA256, "sha256:"), "%s has no whole-file sha256", p.Name)
		byArch[p.Architecture] = append(byArch[p.Architecture], p.Name+"="+p.Version)
	}
	require.Equal(t, map[string][]string{
		"x86_64":  {"pretend-baselayout=1.0.0-r0", "replayout=1.0.0-r0"},
		"aarch64": {"pretend-baselayout=1.0.0-r0", "replayout=1.0.0-r0"},
	}, byArch)
	require.Len(t, l.Contents.Keyrings, 1)
	require.NotEmpty(t, l.Contents.Keyrings[0].Content)

	lockFile := filepath.Join(dir, "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))

	for _, arch := range archs {
		b, err := New(ctx, append(opts, WithArch(arch), WithEnvLockfile(lockFile))...)
		require.NoError(t, err)
		require.NoError(t, b.Compile(ctx))
		_, err = lockedEnvironment(lockFile, b.Configuration.Environment, b.ExtraPackages, arch)
		require.NoError(t, err)
	}

	b, err := New(ctx, append(opts[:len(opts)-1], WithArch(archs[0]), WithEnvLockfile(lockFile))...)
	require.NoError(t, err)
	require.NoError(t, b.Compile(ctx))
	_, err = lockedEnvironment(lockFile, b.Configuration.Environment, b.ExtraPackages, archs[0])
	require.ErrorContains(t, err, "does not match the x86_64 environment")
}

func TestLockTestEnvironment(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("testdata", "envlock"))))
	defer srv.Close()

	tests := []struct {
		name    string
		test    string
		wantErr string
		want    []string
	}{
		{
			name: "main test environment",
			test: `test:
  environment:
    contents:
      repositories:
        - ` + srv.URL + `
      keyring:
        - ` + srv.URL + `/melange.rsa.pub
  pipeline:
    - runs: replayout
`,
			want: []string{"pretend-baselayout", "replayout"},
		},
		{
			name:    "no main test",
			wantErr: "has no main test pipeline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipe := filepath.Join(t.TempDir(), "melange.yaml")
			require.NoError(t, os.WriteFile(recipe, []byte(`package:
  name: replayout
  version: 1.0.0
  epoch: 0
pipeline:
  - runs: echo hello
`+tt.test), 0o644))

			l, err := LockTestEnvironment(ctx, []apko_types.Architecture{apko_types.ParseArchitecture("x86_64")}, LockOptions{},
				WithTestConfig(recipe), WithTestPackageCacheDir(t.TempDir()))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			var got []string
			for _, p := range l.Contents.Packages {
				got = append(got, p.Name)
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
