//go:build !unix

package report

import (
	"os"
	"path/filepath"
)

// Non-Unix builds (Windows) only compile this package; `egret run` and its
// root-versus-build privilege split exist on Linux only. These keep the plain
// behavior: create the directory, write through a temp file and rename.

func openDirNoFollow(dir string, create bool) (*os.File, error) {
	if create {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.Open(dir)
}

func writeFileAt(dir *os.File, name string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(dir.Name(), ".egret-report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir.Name(), name))
}

func appendJobSummary(md string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(md + "\n")
	return err
}
