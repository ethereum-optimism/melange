// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spdx

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"io/fs"
	"runtime/debug"
	"sort"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	purl "github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"chainguard.dev/melange/pkg/sbom"
)

const (
	elfMagic     = "\x7fELF"
	goStdlibName = "stdlib"
	goDevel      = "(devel)"
	goPURLType   = "golang"
)

// goModule is a module compiled into a Go binary, identified by its import
// path and version.
type goModule struct {
	path    string
	version string
	// main is true for the main module of a binary.
	main bool
}

// goBinaryModules returns the modules recorded in the build information of a
// Go binary: the Go toolchain as the "stdlib" module, the main module when it
// has a version, and each dependency at its replacement's path and version.
// Dependencies replaced by a path without a version are skipped.
func goBinaryModules(info *debug.BuildInfo) []goModule {
	var mods []goModule

	if info.GoVersion != "" {
		mods = append(mods, goModule{path: goStdlibName, version: strings.TrimPrefix(info.GoVersion, "go")})
	}

	if info.Main.Path != "" && info.Main.Version != "" && info.Main.Version != goDevel {
		mods = append(mods, goModule{path: info.Main.Path, version: info.Main.Version, main: true})
	}

	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		m := dep
		if dep.Replace != nil {
			m = dep.Replace
		}
		if m.Path == "" || m.Version == "" || m.Version == goDevel {
			continue
		}
		mods = append(mods, goModule{path: m.Path, version: m.Version})
	}

	return mods
}

// goPackageModules scans every regular file below dir in fsys and returns the
// deduplicated Go modules compiled into the Go binaries found there, sorted by
// path and version. A missing dir yields no modules.
func goPackageModules(fsys apkofs.FullFS, dir string) ([]goModule, error) {
	seen := make(map[goModule]struct{})

	err := fs.WalkDir(fsys, dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}

		info, ok := readGoBuildInfo(fsys, name)
		if !ok {
			return nil
		}
		for _, m := range goBinaryModules(info) {
			seen[m] = struct{}{}
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning %s for Go binaries: %w", dir, err)
	}

	mods := make([]goModule, 0, len(seen))
	for m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].path != mods[j].path {
			return mods[i].path < mods[j].path
		}
		return mods[i].version < mods[j].version
	})
	return mods, nil
}

// readGoBuildInfo returns the build information embedded in the file at name.
// It reports false for files that are not ELF files or not Go binaries.
func readGoBuildInfo(fsys apkofs.FullFS, name string) (*debug.BuildInfo, bool) {
	f, err := fsys.OpenReaderAt(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var magic [len(elfMagic)]byte
	if n, _ := f.ReadAt(magic[:], 0); n != len(magic) || string(magic[:]) != elfMagic {
		return nil, false
	}

	info, err := buildinfo.Read(f)
	if err != nil {
		return nil, false
	}
	return info, true
}

// goModulePackage converts a Go module into an SBOM package whose purl follows
// the golang type: the namespace is the module path without its last element,
// and the name is the last element.
func goModulePackage(m goModule, namespace string) (*sbom.Package, error) {
	ns, name := "", m.path
	if i := strings.LastIndex(m.path, "/"); i >= 0 {
		ns, name = m.path[:i], m.path[i+1:]
	}
	pu := &purl.PackageURL{
		Type:      goPURLType,
		Namespace: ns,
		Name:      name,
		Version:   m.version,
	}
	if err := pu.Normalize(); err != nil {
		return nil, fmt.Errorf("building purl for Go module %s@%s: %w", m.path, m.version, err)
	}

	purpose := "LIBRARY"
	if m.main {
		purpose = "APPLICATION"
	}

	return &sbom.Package{
		IDComponents:    []string{goPURLType, m.path, m.version},
		Name:            m.path,
		Version:         m.version,
		Namespace:       namespace,
		LicenseDeclared: spdx.NOASSERTION,
		PURL:            pu,
		PrimaryPurpose:  purpose,
	}, nil
}

// addGoModulePackages adds the Go modules compiled into the binaries under
// dir to doc. Each module is related to the document's described package with
// a CONTAINS relationship.
func addGoModulePackages(doc *sbom.Document, fsys apkofs.FullFS, dir, namespace string) error {
	mods, err := goPackageModules(fsys, dir)
	if err != nil {
		return err
	}

	for _, m := range mods {
		p, err := goModulePackage(m, namespace)
		if err != nil {
			return err
		}
		doc.AddPackage(p)
		doc.AddRelationship(doc.Describes, p, common.TypeRelationshipContains)
	}
	return nil
}
