// Package filesystem implements a Certificate Store on a local directory.
//
// It is meant for development and tests. Layout:
//
//	<root>/<object>/versions/<fingerprint-prefix>-<unix-nanos>/{cert.pem,chain.pem,fullchain.pem,privkey.pem}
//	<root>/<object>/current -> versions/<...>   (symbolic link)
//
// A Put writes a complete new version directory (0700, files 0600, fsynced)
// and then replaces the "current" symlink with a single rename, so a reader
// always sees either the previous complete version or the new one. Older
// versions are pruned after the swap.
package filesystem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/store"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Type is the binding type name.
const Type = "filesystem"

const (
	currentLink = "current"
	versionsDir = "versions"
	certFile    = "cert.pem"
	chainFile   = "chain.pem"
	fullFile    = "fullchain.pem"
	keyFile     = "privkey.pem"
)

// Store is a filesystem-backed store rooted at Root.
type Store struct {
	Root string
	Now  func() time.Time
}

// New returns a store rooted at root. The directory is created (0700) if it
// does not exist.
func New(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("filesystem store root must be absolute: %q", root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create store root: %w", err)
	}
	return &Store{Root: root, Now: time.Now}, nil
}

// Type implements store.Store.
func (s *Store) Type() string { return Type }

// versionRe matches the version directories this store creates.
var versionRe = regexp.MustCompile(`^[0-9a-f]{16}-([0-9]+)$`)

func (s *Store) objectDir(object string) (string, error) {
	if !v1alpha1.IsStoreObjectRef(object) {
		return "", fmt.Errorf("invalid store object name %q", object)
	}
	dir := filepath.Join(s.Root, object)
	// Never follow a pre-existing symbolic link at the object or versions
	// level: writes must stay under the store root.
	for _, p := range []string{dir, filepath.Join(dir, versionsDir)} {
		if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("store path %s is a symbolic link", p)
		}
	}
	return dir, nil
}

// Current implements store.Store.
func (s *Store) Current(_ context.Context, object string) (*store.Info, error) {
	dir, err := s.objectDir(object)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, currentLink, certFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("read current certificate: %w", err)
	}
	leaf, err := store.ParseLeaf(data)
	if err != nil {
		return nil, fmt.Errorf("stored certificate for %q is unreadable: %w", object, err)
	}
	return store.InfoOf(leaf), nil
}

// Put implements store.Store.
func (s *Store) Put(_ context.Context, object string, b store.Bundle) (err error) {
	dir, err := s.objectDir(object)
	if err != nil {
		return err
	}
	leaf, err := store.ParseLeaf(b.Certificate)
	if err != nil {
		return fmt.Errorf("bundle certificate: %w", err)
	}
	if len(b.PrivateKey) == 0 {
		return errors.New("bundle has no private key")
	}
	versions := filepath.Join(dir, versionsDir)
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("random nonce: %w", err)
	}
	final := fmt.Sprintf("%s-%d", store.Fingerprint(leaf)[:16], s.now().UnixNano())
	tmp := filepath.Join(versions, ".tmp-"+final+"-"+hex.EncodeToString(nonce[:]))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return fmt.Errorf("create version directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmp)
		}
	}()
	full := append(append([]byte(nil), b.Certificate...), b.Chain...)
	for name, content := range map[string][]byte{certFile: b.Certificate, chainFile: b.Chain, fullFile: full, keyFile: b.PrivateKey} {
		if err := writeFile(filepath.Join(tmp, name), content); err != nil {
			return err
		}
	}
	if err := fsyncDir(tmp); err != nil {
		return err
	}
	finalPath := filepath.Join(versions, final)
	if err := os.Rename(tmp, finalPath); err != nil {
		return fmt.Errorf("commit version directory: %w", err)
	}
	// Swap the "current" link atomically: create a temporary link, then
	// rename it over the existing one.
	linkTmp := filepath.Join(dir, ".current-"+hex.EncodeToString(nonce[:]))
	if err := os.Symlink(filepath.Join(versionsDir, final), linkTmp); err != nil {
		os.RemoveAll(finalPath)
		return fmt.Errorf("create current link: %w", err)
	}
	if err := os.Rename(linkTmp, filepath.Join(dir, currentLink)); err != nil {
		os.Remove(linkTmp)
		os.RemoveAll(finalPath)
		return fmt.Errorf("swap current link: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return err
	}
	s.prune(versions, final)
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// prune removes version directories this store created that are older
// than keep, plus abandoned temporary directories. Newer versions are left
// alone: if a concurrent Put won the "current" swap, its version must
// survive. Failures are ignored: a leftover old version is harmless.
func (s *Store) prune(versions, keep string) {
	entries, err := os.ReadDir(versions)
	if err != nil {
		return
	}
	keepStamp := versionStamp(keep)
	for _, e := range entries {
		if e.Name() == keep || !e.IsDir() {
			continue
		}
		switch {
		case strings.HasPrefix(e.Name(), ".tmp-"):
			os.RemoveAll(filepath.Join(versions, e.Name()))
		case versionRe.MatchString(e.Name()) && versionStamp(e.Name()) < keepStamp:
			os.RemoveAll(filepath.Join(versions, e.Name()))
		}
	}
}

func versionStamp(name string) int64 {
	m := versionRe.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	return n
}

func writeFile(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	return f.Close()
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
