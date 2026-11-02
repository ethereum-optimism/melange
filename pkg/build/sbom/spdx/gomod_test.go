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

package spdx

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/google/go-cmp/cmp"
	"github.com/spdx/tools-golang/spdx/v2/common"

	build "chainguard.dev/melange/pkg/build/sbom"
	"chainguard.dev/melange/pkg/config"
)

func TestGoBinaryModules(t *testing.T) {
	info := &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "example.com/app", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "example.com/old", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/new", Version: "v1.1.0"}},
			{Path: "example.com/local", Version: "v0.0.0", Replace: &debug.Module{Path: "../local"}},
			{Path: "example.com/devel", Version: "(devel)"},
		},
	}
	want := []goModule{
		{path: "stdlib", version: "1.27.3"},
		{path: "github.com/google/uuid", version: "v1.6.0"},
		{path: "example.com/new", version: "v1.1.0"},
	}
	if diff := cmp.Diff(want, goBinaryModules(info), cmp.AllowUnexported(goModule{})); diff != "" {
		t.Errorf("goBinaryModules() mismatch (-want +got):\n%s", diff)
	}

	info.Main.Version = "v2.0.0"
	got := goBinaryModules(info)
	if !slices.Contains(got, goModule{path: "example.com/app", version: "v2.0.0", main: true}) {
		t.Errorf("goBinaryModules() with a versioned main module = %v, want it to contain example.com/app@v2.0.0", got)
	}
}

func TestGoModulePackagePURL(t *testing.T) {
	tests := []struct {
		name string
		mod  goModule
		want string
	}{
		{
			name: "nested module path",
			mod:  goModule{path: "golang.org/x/text", version: "v0.43.0"},
			want: "pkg:golang/golang.org/x/text@v0.43.0",
		},
		{
			name: "stdlib",
			mod:  goModule{path: "stdlib", version: "1.27.3"},
			want: "pkg:golang/stdlib@1.27.3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := goModulePackage(tt.mod, "test-ns")
			if err != nil {
				t.Fatalf("goModulePackage() error: %v", err)
			}
			if got := p.PURL.ToString(); got != tt.want {
				t.Errorf("PURL = %q, want %q", got, tt.want)
			}
		})
	}
}

// writeGoModule writes a module into a file-based module proxy rooted at proxy.
func writeGoModule(t *testing.T, proxy, modPath, version string, files map[string]string) {
	t.Helper()

	vdir := filepath.Join(proxy, filepath.FromSlash(modPath), "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(name, content string) {
		if err := os.WriteFile(filepath.Join(vdir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gomod := "module " + modPath + "\n\ngo 1.21\n"
	mustWrite(version+".info", `{"Version":"`+version+`","Time":"2024-01-01T00:00:00Z"}`)
	mustWrite(version+".mod", gomod)
	mustWrite("list", version+"\n")

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	prefix := modPath + "@" + version + "/"
	all := map[string]string{"go.mod": gomod}
	for name, content := range files {
		all[name] = content
	}
	for name, content := range all {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	mustWrite(version+".zip", zbuf.String())
}

// buildGoFixture writes a package output tree under outDir with two Go
// binaries: gotest/usr/bin/app in the main package and gotest-extra/usr/bin/tool
// in a subpackage. Both use example.com/dep, which is replaced by
// example.com/fork. It returns the Go toolchain version used to build them.
func buildGoFixture(t *testing.T, outDir string) string {
	t.Helper()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}

	root := t.TempDir()
	modcache := filepath.Join(root, "modcache")
	t.Cleanup(func() {
		// Restore write permissions on the module cache before cleanup.
		_ = filepath.WalkDir(modcache, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	proxy := filepath.Join(root, "proxy")
	writeGoModule(t, proxy, "example.com/dep", "v1.2.3", map[string]string{
		"dep.go": "package dep\n\nfunc Name() string { return \"dep\" }\n",
	})
	writeGoModule(t, proxy, "example.com/fork", "v1.2.4", map[string]string{
		"fork.go": "package dep\n\nfunc Name() string { return \"fork\" }\n",
	})

	src := filepath.Join(root, "src")
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.2.3\n\n" +
			"replace example.com/dep => example.com/fork v1.2.4\n",
		"cmd/app/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\tdep \"example.com/dep\"\n)\n\n" +
			"func main() { fmt.Println(dep.Name()) }\n",
		"cmd/tool/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\tdep \"example.com/dep\"\n)\n\n" +
			"func main() { fmt.Println(dep.Name()) }\n",
	}
	for name, content := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	env := append(os.Environ(),
		"GOPROXY=file://"+proxy,
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
		"GOMODCACHE="+modcache,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(goBin, args...)
		cmd.Dir = src
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	bins := map[string]string{
		"gotest/usr/bin/app":        "./cmd/app",
		"gotest-extra/usr/bin/tool": "./cmd/tool",
	}
	for out, pkg := range bins {
		dst := filepath.Join(outDir, filepath.FromSlash(out))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		run("build", "-o", dst, pkg)
	}

	// Non-ELF content under the package directory.
	readme := filepath.Join(outDir, "gotest", "usr", "share", "doc", "readme.txt")
	if err := os.MkdirAll(filepath.Dir(readme), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readme, []byte("not a binary\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(goBin, "env", "GOVERSION")
	cmd.Dir = src
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func golangPURLs(doc *spdx.Document) []string {
	var purls []string
	for _, p := range doc.Packages {
		for _, r := range p.ExternalRefs {
			if strings.HasPrefix(r.Locator, "pkg:golang/") {
				purls = append(purls, r.Locator)
			}
		}
	}
	slices.Sort(purls)
	return purls
}

func TestGenerateSBOMIncludesGoModules(t *testing.T) {
	ctx := context.Background()
	outDir := t.TempDir()
	goVersion := buildGoFixture(t, outDir)

	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "gotest",
			Version: "1.0.0",
			Epoch:   0,
			Copyright: []config.Copyright{
				{License: "MIT"},
			},
		},
		Subpackages: []config.Subpackage{
			{Name: "gotest-extra"},
		},
	}
	genCtx := &build.GeneratorContext{
		Configuration:   cfg,
		WorkspaceDir:    outDir,
		OutputFS:        apkofs.DirFS(ctx, outDir),
		SourceDateEpoch: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Namespace:       "test-ns",
		Arch:            "x86_64",
	}

	gen := &Generator{}
	docs, err := gen.GenerateSPDX(ctx, genCtx)
	if err != nil {
		t.Fatalf("GenerateSPDX() error: %v", err)
	}

	wantPURLs := []string{
		"pkg:golang/example.com/fork@v1.2.4",
		"pkg:golang/stdlib@" + strings.TrimPrefix(goVersion, "go"),
	}
	for _, name := range []string{"gotest", "gotest-extra"} {
		doc := docs[name]
		if diff := cmp.Diff(wantPURLs, golangPURLs(&doc)); diff != "" {
			t.Errorf("%s: golang purls mismatch (-want +got):\n%s", name, diff)
		}

		apkID := doc.DocumentDescribes[0]
		for _, p := range doc.Packages {
			if len(golangPURLs(&spdx.Document{Packages: []spdx.Package{p}})) == 0 {
				continue
			}
			want := spdx.Relationship{Element: apkID, Type: common.TypeRelationshipContains, Related: p.ID}
			if !slices.Contains(doc.Relationships, want) {
				t.Errorf("%s: missing relationship %+v", name, want)
			}
		}
	}

	first, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	again, err := gen.GenerateSPDX(ctx, genCtx)
	if err != nil {
		t.Fatalf("second GenerateSPDX() error: %v", err)
	}
	second, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("GenerateSPDX() output differs between runs")
	}
}
