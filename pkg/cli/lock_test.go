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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/lock"
	"github.com/stretchr/testify/require"
)

func runLockCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := lockCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&testWriter{t})
	cmd.SetErr(&testWriter{t})
	return cmd.ExecuteContext(context.Background())
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestLockCmd(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "build", "testdata", "envlock"))))
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
      - pretend-baselayout
pipeline:
  - runs: echo hello
test:
  environment:
    contents:
      repositories:
        - `+srv.URL+`
      keyring:
        - `+srv.URL+`/melange.rsa.pub
      packages:
        - pretend-baselayout
  pipeline:
    - runs: replayout
`), 0o644))
	out := filepath.Join(dir, "out.lock.json")
	common := []string{"--arch", "x86_64", "--apk-cache-dir", t.TempDir(), "-o", out}

	t.Run("ignore-signatures is refused", func(t *testing.T) {
		err := runLockCmd(t, append([]string{recipe, "--ignore-signatures"}, common...)...)
		require.ErrorContains(t, err, "--allow-unverified-lock")
		_, err = os.Stat(out)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("allow-unverified-lock marks the lock", func(t *testing.T) {
		require.NoError(t, runLockCmd(t, append([]string{recipe, "--ignore-signatures", "--allow-unverified-lock"}, common...)...))
		l, err := lock.FromFile(out)
		require.NoError(t, err)
		require.True(t, l.UnverifiedIndexes)
	})

	t.Run("allow-unverified-lock needs ignore-signatures", func(t *testing.T) {
		require.ErrorContains(t, runLockCmd(t, append([]string{recipe, "--allow-unverified-lock"}, common...)...), "needs --ignore-signatures")
	})

	t.Run("test environment with the package under test", func(t *testing.T) {
		require.NoError(t, runLockCmd(t, append([]string{"--test", recipe, "replayout"}, common...)...))
		l, err := lock.FromFile(out)
		require.NoError(t, err)
		require.False(t, l.UnverifiedIndexes)
		var names []string
		for _, p := range l.Contents.Packages {
			names = append(names, p.Name)
		}
		require.ElementsMatch(t, []string{"pretend-baselayout", "replayout"}, names)
	})

	t.Run("package argument without test", func(t *testing.T) {
		require.ErrorContains(t, runLockCmd(t, append([]string{recipe, "replayout"}, common...)...), "only accepted with --test")
	})
}
