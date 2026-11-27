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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

// envLockRepo serves testdata/envlock and records the requested paths.
type envLockRepo struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newEnvLockRepo(t *testing.T, extra http.HandlerFunc) *envLockRepo {
	t.Helper()
	r := &envLockRepo{}
	files := http.FileServer(http.Dir(filepath.Join("testdata", "envlock")))
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		setTestETag(w, req)
		if extra != nil && req.URL.Path == "/wrong.rsa.pub" {
			extra(w, req)
			return
		}
		files.ServeHTTP(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *envLockRepo) requested(substr string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, p := range r.paths {
		if strings.Contains(p, substr) {
			out = append(out, p)
		}
	}
	return out
}

func buildGuest(ctx context.Context, b *Build, ic apko_types.ImageConfiguration, tmp string) error {
	bc, err := b.newGuestContext(ctx, ic, tarfs.New(), tmp)
	if err != nil {
		return err
	}
	return bc.BuildImage(ctx)
}

// TestEnvLockUnverifiedIndexes locks an environment whose repository index is
// not signed by the configured key.
func TestEnvLockUnverifiedIndexes(t *testing.T) {
	ctx := context.Background()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	wrong := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	srv := newEnvLockRepo(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(wrong) })
	ic := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{
		Repositories: []string{srv.URL},
		Keyring:      []string{srv.URL + "/wrong.rsa.pub"},
		Packages:     []string{"replayout"},
	}}
	arch := apko_types.ParseArchitecture("x86_64")

	verified := &Build{Arch: arch, ApkCacheDir: t.TempDir(), Configuration: &config.Configuration{}}
	_, err = generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, apkoOpts: verified.guestApkoOptions("")}})
	require.Error(t, err, "locking against an index signed by another key succeeded")

	laxCache := t.TempDir()
	lax := &Build{Arch: arch, ApkCacheDir: laxCache, IgnoreSignatures: true, Configuration: &config.Configuration{}}
	l, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, apkoOpts: lax.guestApkoOptions("")}})
	require.NoError(t, err)
	require.True(t, l.UnverifiedIndexes, "lock resolved without signature verification is not marked")
	lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))

	strict := &Build{Arch: arch, ApkCacheDir: t.TempDir(), Guest: GuestEnvironment{LockFile: lockFile, RequireStrongChecksums: true}, Configuration: &config.Configuration{}}
	require.ErrorContains(t, buildGuest(ctx, strict, ic, t.TempDir()), "generated without verifying repository index signatures")

	offline := &Build{Arch: arch, ApkCacheDir: laxCache, Guest: GuestEnvironment{LockFile: lockFile, Offline: true}, Configuration: &config.Configuration{}}
	err = buildGuest(ctx, offline, ic, t.TempDir())
	require.ErrorContains(t, err, "unable to read the repository indexes from the apk cache", "a badly signed cached index was treated as missing")
}

// TestEnvLockMissingRemoteIndex builds offline from a lock whose local
// repository index is available but whose remote one is not.
func TestEnvLockMissingRemoteIndex(t *testing.T) {
	ctx := context.Background()
	srv := newEnvLockRepo(t, nil)
	local := copyDir(t, filepath.Join("testdata", "envlock"))
	arch := apko_types.ParseArchitecture("x86_64")
	ic := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{
		Repositories: []string{srv.URL},
		Keyring:      []string{srv.URL + "/melange.rsa.pub"},
		Packages:     []string{"replayout"},
	}}
	cache := t.TempDir()
	b := &Build{Arch: arch, ApkCacheDir: cache, ExtraRepos: []string{local}, Configuration: &config.Configuration{}}
	l, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, extra: b.envAppend(), apkoOpts: b.guestApkoOptions("")}})
	require.NoError(t, err)
	lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))
	b.Guest = GuestEnvironment{LockFile: lockFile}
	require.NoError(t, buildGuest(ctx, b, ic, t.TempDir()))
	srv.Close()
	removeCachedIndexes(t, cache)

	t.Setenv("MELANGE_VERSIONED_SHLIB_DEPENDS", "1")
	b = &Build{Arch: arch, ApkCacheDir: cache, ExtraRepos: []string{local}, Guest: GuestEnvironment{LockFile: lockFile, Offline: true}, Configuration: &config.Configuration{}}
	err = buildGuest(ctx, b, ic, t.TempDir())
	require.ErrorContains(t, err, "the APKINDEX of "+srv.URL+" is not in the apk cache")
}

// TestEnvLockResolverReadsCacheOnly builds online from a lock and requires
// that the package resolver comes from the cache, not from a live index.
func TestEnvLockResolverReadsCacheOnly(t *testing.T) {
	ctx := context.Background()
	fx := newEnvLockFixture(t)
	srv := newEnvLockRepo(t, nil)
	arch := apko_types.ParseArchitecture("x86_64")
	ic := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{
		Repositories: []string{srv.URL},
		Keyring:      []string{srv.URL + "/melange.rsa.pub"},
		Packages:     []string{"replayout"},
	}}
	cache := t.TempDir()
	b := &Build{Arch: arch, ApkCacheDir: cache, Configuration: &config.Configuration{}}
	l, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, apkoOpts: b.guestApkoOptions("")}})
	require.NoError(t, err)
	lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))

	t.Run("index in the cache", func(t *testing.T) {
		before := len(srv.requested("APKINDEX"))
		b := &Build{Arch: arch, ApkCacheDir: cache, Guest: GuestEnvironment{LockFile: lockFile}, Configuration: &config.Configuration{}}
		require.NoError(t, buildGuest(ctx, b, ic, t.TempDir()))
		require.Len(t, srv.requested("APKINDEX"), before, "online build from a lock fetched a repository index")
		require.NotNil(t, b.PkgResolver)
	})
	t.Run("index not in the cache", func(t *testing.T) {
		removeCachedIndexes(t, cache)
		before := len(srv.requested("APKINDEX"))
		b := &Build{Arch: arch, ApkCacheDir: cache, Guest: GuestEnvironment{LockFile: lockFile}, Configuration: &config.Configuration{}}
		require.NoError(t, buildGuest(ctx, b, ic, t.TempDir()))
		require.Len(t, srv.requested("APKINDEX"), before, "online build from a lock fetched a repository index")
		require.Nil(t, b.PkgResolver)
	})
	t.Run("cached index that fails to load", func(t *testing.T) {
		cache := copyDir(t, fx.indexedCache)
		indexes := cachedIndexes(t, cache)
		require.NotEmpty(t, indexes)
		for _, p := range indexes {
			require.NoError(t, os.WriteFile(p, []byte("not an index"), 0o644))
		}
		b := &Build{Arch: arch, ApkCacheDir: cache, Guest: GuestEnvironment{LockFile: fx.lockFile, Offline: true}, Configuration: &config.Configuration{}}
		require.ErrorContains(t, buildGuest(ctx, b, fx.ic, t.TempDir()), "unable to read the repository indexes from the apk cache")
	})
}

// fileOnlyGetter fetches packages from testdata/envlock and cannot compute
// their whole-file sha256.
type fileOnlyGetter struct{}

func (fileOnlyGetter) GetPackage(ctx context.Context, pkg apk.InstallablePackage) (*expandapk.APKExpanded, error) {
	b, err := os.ReadFile(filepath.Join("testdata", "envlock", "x86_64", filepath.Base(pkg.URL())))
	if err != nil {
		return nil, err
	}
	return expandapk.ExpandApk(ctx, bytes.NewReader(b), "")
}

func TestGenerateEnvLockRequiresSHA256(t *testing.T) {
	ctx := context.Background()
	srv := newEnvLockRepo(t, nil)
	arch := apko_types.ParseArchitecture("x86_64")
	ic := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{
		Repositories: []string{srv.URL},
		Keyring:      []string{srv.URL + "/melange.rsa.pub"},
		Packages:     []string{"replayout"},
	}}
	b := &Build{Arch: arch, ApkCacheDir: t.TempDir(), Configuration: &config.Configuration{}}
	_, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, apkoOpts: append(b.guestApkoOptions(""), apko_build.WithPackageGetter(fileOnlyGetter{}))}})
	require.ErrorContains(t, err, "sha256")
}

func TestEnvLockTestWithoutMainTest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	recipe := filepath.Join(dir, "melange.yaml")
	require.NoError(t, os.WriteFile(recipe, []byte(`package:
  name: replayout
  version: 1.0.0
  epoch: 0
pipeline:
  - runs: echo hello
`), 0o644))
	lockFile := filepath.Join(dir, "melange.lock.json")
	require.NoError(t, (&lock.Lock{Version: "v1"}).SaveToFile(lockFile))

	tc, err := NewTest(ctx, WithTestConfig(recipe), WithTestEnvLockfile(lockFile),
		WithTestArch(apko_types.ParseArchitecture("x86_64")), WithTestPackageCacheDir(t.TempDir()),
		WithTestWorkspaceDir(t.TempDir()))
	require.NoError(t, err)
	require.ErrorContains(t, tc.TestPackage(ctx), "has no main test pipeline")
}

func TestEnvLockAppendedKeyNotLocked(t *testing.T) {
	ctx := context.Background()
	srv := newEnvLockRepo(t, nil)
	arch := apko_types.ParseArchitecture("x86_64")
	ic := apko_types.ImageConfiguration{Contents: apko_types.ImageContents{
		Repositories: []string{srv.URL},
		Keyring:      []string{srv.URL + "/melange.rsa.pub"},
		Packages:     []string{"replayout"},
	}}
	b := &Build{Arch: arch, ApkCacheDir: t.TempDir(), Configuration: &config.Configuration{}}
	l, err := generateEnvLock(ctx, "melange.yaml", []envToLock{{arch: arch, ic: ic, extra: b.envAppend(), apkoOpts: b.guestApkoOptions("")}})
	require.NoError(t, err)
	lockFile := filepath.Join(t.TempDir(), "melange.lock.json")
	require.NoError(t, l.SaveToFile(lockFile))

	key, err := os.ReadFile(filepath.Join("testdata", "envlock", "melange.rsa.pub"))
	require.NoError(t, err)
	extraKey := filepath.Join(t.TempDir(), "extra.rsa.pub")
	require.NoError(t, os.WriteFile(extraKey, key, 0o644))
	withKey := &Build{Arch: arch, ApkCacheDir: t.TempDir(), ExtraKeys: []string{extraKey}, Guest: GuestEnvironment{LockFile: lockFile}, Configuration: &config.Configuration{}}
	_, err = withKey.newGuestContext(ctx, ic, tarfs.New(), t.TempDir())
	require.ErrorContains(t, err, "does not match", "a lock without the --keyring-append key was accepted")

	withRepo := &Build{Arch: arch, ApkCacheDir: t.TempDir(), ExtraRepos: []string{copyDir(t, filepath.Join("testdata", "envlock"))}, Guest: GuestEnvironment{LockFile: lockFile}, Configuration: &config.Configuration{}}
	_, err = withRepo.newGuestContext(ctx, ic, tarfs.New(), t.TempDir())
	require.ErrorContains(t, err, "does not match", "a lock without the --repository-append repository was accepted")
}
