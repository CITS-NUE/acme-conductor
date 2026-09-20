package runner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// WriteResult prints res as one JSON line to stdout and, when path is not
// empty, writes the same document atomically to path (temporary file in
// the same directory, fsync, rename).
func WriteResult(res *v1alpha1.Result, path string, stdout io.Writer) error {
	line, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if stdout != nil {
		if _, err := stdout.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write result to stdout: %w", err)
		}
	}
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create result file: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write result file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sync result file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("commit result file: %w", err)
	}
	return nil
}
