package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
)

// maxStateFileSize bounds files copied between the state and work
// directories. ACME account files are a few kilobytes.
const maxStateFileSize = 1 << 20

// workDirPrefix is the name prefix of per-run work directories.
const workDirPrefix = "run-"

// prepareWorkDir creates a private per-run directory under parent and
// returns it with a cleanup function that removes it entirely. The
// certificate private key only ever exists inside this directory (and in
// the Store), so cleanup is what destroys it.
//
// Before creating the new directory, per-run directories older than
// staleAfter are removed: a Runner that was killed with an uncatchable
// signal cannot run its own cleanup, and a work directory on anything
// other than a per-process tmpfs would otherwise keep key material.
func prepareWorkDir(parent, runID string, staleAfter time.Duration) (string, func(), error) {
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("create work parent: %w", err)
	}
	sweepStaleWorkDirs(parent, staleAfter, time.Now())
	dir, err := os.MkdirTemp(parent, workDirPrefix+runID+"-")
	if err != nil {
		return "", nil, fmt.Errorf("create work directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("restrict work directory: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// sweepStaleWorkDirs removes per-run directories under parent whose
// modification time is older than staleAfter. A live run never exceeds
// the lego timeout, so callers pass a multiple of it. Failures are logged
// by omission only: sweeping is best effort.
func sweepStaleWorkDirs(parent string, staleAfter time.Duration, now time.Time) {
	if staleAfter <= 0 {
		return
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), workDirPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > staleAfter {
			_ = os.RemoveAll(filepath.Join(parent, e.Name()))
		}
	}
}

// copyTree copies the regular files and directories under src to dst,
// creating dst. Symbolic links and special files are skipped. Directories
// are created 0700 and files 0600 regardless of their source mode.
func copyTree(src, dst string) error {
	// The root may be a symbolic link (the state directory's "accounts"
	// pointer); it is resolved once here. Links below the root are skipped.
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	src = resolved
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

// accountVersionsDir holds the versioned copies of the ACME account state;
// <stateDir>/accounts is a symbolic link to the current one.
const accountVersionsDir = "accounts.d"

// persistAccounts publishes the "accounts" subtree of the work directory as
// the current ACME account state:
//
//  1. copy it to <stateDir>/accounts.d/<unix-nanos>-<nonce>/ (files 0600,
//     fsynced), fsync that directory;
//  2. point <stateDir>/accounts at it by creating a temporary symbolic
//     link and renaming it over "accounts" (one atomic step), fsync
//     stateDir;
//  3. remove older versions.
//
// There is no moment at which "accounts" is absent: a crash before step 2
// leaves the previous pointer intact, a crash after it leaves the new one.
// A pre-existing plain "accounts" directory (not a link) is moved into
// accounts.d before the swap so nothing is lost.
func persistAccounts(work, stateDir string) error {
	src := filepath.Join(work, lego.AccountsDir)
	if _, err := os.Lstat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	versions := filepath.Join(stateDir, accountVersionsDir)
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return err
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	version := fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(nonce[:]))
	fresh := filepath.Join(versions, version)
	if err := copyTree(src, fresh); err != nil {
		os.RemoveAll(fresh)
		return err
	}
	if err := fsyncDir(fresh); err != nil {
		os.RemoveAll(fresh)
		return err
	}
	final := filepath.Join(stateDir, lego.AccountsDir)
	if info, err := os.Lstat(final); err == nil && info.Mode()&os.ModeSymlink == 0 {
		// Legacy layout: keep the directory as an unreferenced version.
		if err := os.Rename(final, filepath.Join(versions, "legacy-"+version)); err != nil {
			os.RemoveAll(fresh)
			return err
		}
	}
	linkTmp := filepath.Join(stateDir, ".accounts-"+hex.EncodeToString(nonce[:]))
	if err := os.Symlink(filepath.Join(accountVersionsDir, version), linkTmp); err != nil {
		os.RemoveAll(fresh)
		return err
	}
	if err := os.Rename(linkTmp, final); err != nil {
		os.Remove(linkTmp)
		os.RemoveAll(fresh)
		return err
	}
	if err := fsyncDir(stateDir); err != nil {
		return err
	}
	// Prune every version except the one now referenced.
	entries, err := os.ReadDir(versions)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.Name() != version && e.IsDir() {
			_ = os.RemoveAll(filepath.Join(versions, e.Name()))
		}
	}
	return nil
}

func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
