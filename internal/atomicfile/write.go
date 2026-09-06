package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Write persists a complete file as a transaction in the destination
// directory. The previous complete value is kept at path+".previous-good".
// The temporary file is fsync'ed before the atomic replacement, so a crash
// cannot leave a partially-written target file.
func Write(path string, data []byte, perm fs.FileMode) error {
	if path == "" {
		return errors.New("atomicfile: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("atomicfile: mkdir %s: %w", dir, err)
	}

	if old, err := os.ReadFile(path); err == nil {
		st, statErr := os.Stat(path)
		backupPerm := perm
		if statErr == nil {
			backupPerm = st.Mode().Perm()
		}
		if err := writeReplace(path+".previous-good", old, backupPerm); err != nil {
			return fmt.Errorf("atomicfile: previous-good backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("atomicfile: read current %s: %w", path, err)
	}

	if err := writeReplace(path, data, perm); err != nil {
		return fmt.Errorf("atomicfile: replace %s: %w", path, err)
	}
	return nil
}

// WriteDirect persists a complete file as an atomic transaction in the destination
// directory without creating a .previous-good backup. This is suitable for system
// files like /etc/hosts where the caller manages backups in a dedicated user directory.
func WriteDirect(path string, data []byte, perm fs.FileMode) error {
	if path == "" {
		return errors.New("atomicfile: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("atomicfile: mkdir %s: %w", dir, err)
	}
	if err := writeReplace(path, data, perm); err != nil {
		return fmt.Errorf("atomicfile: replace %s: %w", path, err)
	}
	return nil
}

func writeReplace(path string, data []byte, perm fs.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()

	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}
