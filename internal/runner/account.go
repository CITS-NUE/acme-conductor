package runner

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/CITS-NUE/acme-conductor/internal/fslock"
	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// accountGenerationsDir is the top-level directory under the legacy
// stateDir that holds every generation-scoped ACME account root (issue
// #42): stateDir/acme-accounts/<binding>/<generation>.
const accountGenerationsDir = "acme-accounts"

// accountsRoot returns the ACME account state directory to use for one
// job: stateDir itself, unchanged, when account is nil (the legacy,
// unversioned account state), or
// stateDir/acme-accounts/<binding>/<generation> when it names a
// generation. The generation path is built one component at a time and
// every component is Lstat-checked: it must already be a real directory,
// or absent (in which case it is created 0700). A component that is a
// symbolic link, or exists as anything other than a directory, is refused
// rather than followed or replaced, so a pre-planted link anywhere along
// the path can never make the Runner read or write outside stateDir.
// binding is already validated by the contract (a DNS-label-like name)
// and the generation is a bounded integer, so neither can inject an extra
// path component or a traversal sequence.
func accountsRoot(stateDir, binding string, account *v1alpha1.ACMEAccountRef) (string, error) {
	if account == nil {
		return stateDir, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	dir := stateDir
	for _, comp := range []string{accountGenerationsDir, binding, strconv.FormatInt(account.Generation, 10)} {
		next := filepath.Join(dir, comp)
		if err := mkdirRealComponent(next); err != nil {
			return "", err
		}
		dir = next
	}
	return dir, nil
}

// mkdirRealComponent ensures path exists as a real directory (never a
// symbolic link) and is not anything else, creating it 0700 if absent.
func mkdirRealComponent(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: %s is not a real directory", ErrAccountsCorrupt, path)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// accountRegistered reports whether the ACME account state under dir (a
// work directory that loadAccounts has just populated, or a generation
// root directly) already holds a registered account: at least one
// accounts/<host>/<email>/account.json whose registration.uri is a
// non-empty string — the shape the real lego CLI writes only after a
// successful newAccount. Presence of the file alone is never enough: an
// account.json can exist from a partial or failed registration attempt,
// and this check must never mistake that for success. Reading is bounded
// like every other state file this package copies; a file that cannot be
// read or parsed is treated as not registered rather than as an error, so
// a lightly corrupted or foreign entry never blocks a legitimate run
// (that a directory holds a proper account is exactly what this function
// exists to confirm).
func accountRegistered(dir string) bool {
	return accountsTreeRegistered(filepath.Join(dir, lego.AccountsDir))
}

// publishedAccountRegistered reports whether the account state durably
// published under stateRoot (the version its "accounts" link points at,
// read under the shared state lock like loadAccounts) holds a registered
// account. A provisioning run consults it after persistAccounts: lego
// having registered the account in the work directory is not enough to
// report the generation as registered, because the next run can only
// reuse what was actually published.
func publishedAccountRegistered(ctx context.Context, stateRoot string) (bool, error) {
	lock, err := fslock.Shared(ctx, filepath.Join(stateRoot, stateLockFile))
	if err != nil {
		return false, err
	}
	defer lock.Unlock()
	current, err := validateAccountsLayout(stateRoot)
	if err != nil || current == "" {
		return false, err
	}
	return accountsTreeRegistered(current), nil
}

// accountsTreeRegistered is accountRegistered for a tree laid out like
// lego's "accounts" directory itself (<host>/<email>/account.json).
func accountsTreeRegistered(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if found {
			return filepath.SkipAll
		}
		if err != nil || d.IsDir() || d.Name() != "account.json" {
			return nil
		}
		data, err := readBounded(path, maxStateFileSize)
		if err != nil {
			return nil
		}
		var doc struct {
			Registration struct {
				URI string `json:"uri"`
			} `json:"registration"`
		}
		if json.Unmarshal(data, &doc) == nil && doc.Registration.URI != "" {
			found = true
		}
		return nil
	})
	return found
}

// maxProvisioningKeyFileSize bounds a provisioning private key file (a PEM
// PKCS #8 block for a 32-byte X25519 key is a few hundred bytes); the same
// order of magnitude as the result-signing key file.
const maxProvisioningKeyFileSize = 16 * 1024

// loadProvisioningKeys reads every configured account-provisioning private
// key file, bounded like the result-signing key, and indexes it by
// ProvisioningKeyID so a sealed payload can select the one it was sealed
// to. Keys are read lazily by the caller, only for a job that actually
// carries a provisioning payload: they never touch disk on a plain
// issuance or renewal run.
func loadProvisioningKeys(cfg *config.AccountProvisioning) (map[string]*ecdh.PrivateKey, error) {
	keys := make(map[string]*ecdh.PrivateKey, len(cfg.PrivateKeyFiles))
	for _, path := range cfg.PrivateKeyFiles {
		data, err := readBounded(path, maxProvisioningKeyFileSize)
		if err != nil {
			return nil, err
		}
		key, err := v1alpha1.ParseProvisioningPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		keys[v1alpha1.ProvisioningKeyID(key.PublicKey())] = key
	}
	return keys, nil
}
