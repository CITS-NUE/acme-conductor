package v1alpha1

import (
	"errors"
	"fmt"
	"io"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
)

// MaxDocumentSize bounds the size of a JobSpec or Result document. Both are
// small; anything larger is treated as hostile input.
const MaxDocumentSize = 64 * 1024

// Decoding errors. The strict checks live in internal/strictjson; the
// sentinels are re-exported here so callers of this package can classify
// failures without importing an internal package.
var (
	ErrDocumentTooLarge = errors.New("document exceeds maximum size")
	ErrTrailingData     = strictjson.ErrTrailingData
	ErrDuplicateKey     = strictjson.ErrDuplicateKey
	ErrNotAnObject      = strictjson.ErrNotAnObject
	ErrTooDeep          = strictjson.ErrTooDeep
)

// MaxNestingDepth bounds the nesting of objects and arrays in a document.
const MaxNestingDepth = strictjson.MaxNestingDepth

// DecodeJobSpec strictly decodes and validates a JobSpec.
func DecodeJobSpec(r io.Reader) (*JobSpec, error) {
	var spec JobSpec
	if err := decodeStrict(r, &spec); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

// DecodeResult strictly decodes and validates a Result.
func DecodeResult(r io.Reader) (*Result, error) {
	var res Result
	if err := decodeStrict(r, &res); err != nil {
		return nil, err
	}
	if err := res.Validate(); err != nil {
		return nil, err
	}
	return &res, nil
}

// decodeStrict reads at most MaxDocumentSize bytes and decodes a single JSON
// object into v, rejecting unknown fields, duplicate keys, trailing data
// and excessive nesting.
func decodeStrict(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentSize+1))
	if err != nil {
		return fmt.Errorf("read document: %w", err)
	}
	if len(data) > MaxDocumentSize {
		return ErrDocumentTooLarge
	}
	return strictjson.Unmarshal(data, v)
}
