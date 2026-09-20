package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
)

// maxStateFileSize bounds files copied between the state and work
// directories. ACME account files are a few kilobytes.
const maxStateFileSize = 1 << 20

// prepareWorkDir creates a private per-run directory under parent and
// returns it with a cleanup function that removes it entirely. The
// certificate private key only ever exists inside this directory (and in
// the Store), so cleanup is what destroys it.
func prepareWorkDir(parent, runID string) (string, func(), error) {
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("create work parent: %w", err)
	}
	dir, err := os.MkdirTemp(parent, "run-"+runID+"-")
	if err != nil {
		return "", nil, fmt.Errorf("create work directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("restrict work directory: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// copyTree copies the regular files and directories under src to dst,
// creating dst. Symbolic links and special files are skipped. Directories
// are created 0700 and files 0600 regardless of their source mode.
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular():
			return copyFile(path, target)
		default:
			return nil
		}
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if st.Size() > maxStateFileSize {
		return fmt.Errorf("%s exceeds %d bytes", src, maxStateFileSize)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, maxStateFileSize)); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// persistAccounts copies the "accounts" subtree of the work directory back
// into stateDir, replacing the previous copy with a rename so a crash in
// the middle leaves either the old or the new state.
func persistAccounts(work, stateDir string) error {
	src := filepath.Join(work, lego.AccountsDir)
	if _, err := os.Lstat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	suffix := hex.EncodeToString(nonce[:])
	fresh := filepath.Join(stateDir, ".accounts-new-"+suffix)
	if err := copyTree(src, fresh); err != nil {
		os.RemoveAll(fresh)
		return err
	}
	final := filepath.Join(stateDir, lego.AccountsDir)
	old := filepath.Join(stateDir, ".accounts-old-"+suffix)
	if err := os.Rename(final, old); err != nil && !errors.Is(err, os.ErrNotExist) {
		os.RemoveAll(fresh)
		return err
	}
	if err := os.Rename(fresh, final); err != nil {
		// Try to put the old state back.
		_ = os.Rename(old, final)
		os.RemoveAll(fresh)
		return err
	}
	_ = os.RemoveAll(old)
	return nil
}
