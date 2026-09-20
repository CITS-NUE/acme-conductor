package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/fslock"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
)

// maxStateFileSize bounds files copied between the state and work
// directories. ACME account files are a few kilobytes.
const maxStateFileSize = 1 << 20

// workDirPrefix is the name prefix of per-run work directories.
const workDirPrefix = "run-"

// deadlineFile, inside a per-run directory, records the Unix time after
// which the directory may be swept by any Runner, so that Runners with
// different timeouts sharing one workDir never sweep each other's live
// runs.
const deadlineFile = ".sweep-after"

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
	now := time.Now()
	sweepStaleWorkDirs(parent, staleAfter, now)
	dir, err := os.MkdirTemp(parent, workDirPrefix+runID+"-")
	if err != nil {
		return "", nil, fmt.Errorf("create work directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("restrict work directory: %w", err)
	}
	if staleAfter > 0 {
		deadline := strconv.FormatInt(now.Add(staleAfter).Unix(), 10)
		if err := os.WriteFile(filepath.Join(dir, deadlineFile), []byte(deadline+"\n"), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", nil, fmt.Errorf("record work directory deadline: %w", err)
		}
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// sweepStaleWorkDirs removes per-run directories under parent that are
// past their recorded deadline (deadlineFile written by the creator). A
// directory without a readable deadline falls back to its modification
// time plus staleAfter. Sweeping is best effort.
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
		dir := filepath.Join(parent, e.Name())
		expired := false
		if data, err := os.ReadFile(filepath.Join(dir, deadlineFile)); err == nil {
			if secs, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				expired = now.Unix() > secs
			}
		} else if info, err := e.Info(); err == nil {
			expired = now.Sub(info.ModTime()) > staleAfter
		}
		if expired {
			_ = os.RemoveAll(dir)
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

// stateLockFile serializes publishers of the account state and keeps a
// reader (loadAccounts) consistent with them.
const stateLockFile = ".lock"

// loadAccounts copies the current ACME account state from stateDir into
// the work directory under a shared lock, so a concurrent publisher cannot
// prune the version being read. A missing state is not an error.
func loadAccounts(stateDir, work string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	lock, err := fslock.Shared(filepath.Join(stateDir, stateLockFile))
	if err != nil {
		return err
	}
	defer lock.Unlock()
	err = copyTree(filepath.Join(stateDir, lego.AccountsDir), filepath.Join(work, lego.AccountsDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

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
// Every directory whose entries change (the version, accounts.d, stateDir)
// is fsynced in order, so the same holds for a power loss. The whole
// operation runs under an exclusive lock on stateDir, so two publishers
// are serialized and step 3 can never prune the version a concurrent
// publisher just referenced: the last one to take the lock wins. A
// pre-existing plain "accounts" directory (not a link) is moved into
// accounts.d before the swap so nothing is lost.
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
	lock, err := fslock.Exclusive(filepath.Join(stateDir, stateLockFile))
	if err != nil {
		return err
	}
	defer lock.Unlock()
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
	if err := fsyncDir(versions); err != nil {
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
