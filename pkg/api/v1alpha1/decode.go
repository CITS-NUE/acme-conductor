package v1alpha1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxDocumentSize bounds the size of a JobSpec or Result document. Both are
// small; anything larger is treated as hostile input.
const MaxDocumentSize = 64 * 1024

// Decoding errors.
var (
	ErrDocumentTooLarge = errors.New("document exceeds maximum size")
	ErrTrailingData     = errors.New("unexpected data after JSON document")
	ErrDuplicateKey     = errors.New("duplicate object key")
	ErrNotAnObject      = errors.New("document is not a JSON object")
)

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
// object into v, rejecting unknown fields, duplicate keys and trailing data.
func decodeStrict(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentSize+1))
	if err != nil {
		return fmt.Errorf("read document: %w", err)
	}
	if len(data) > MaxDocumentSize {
		return ErrDocumentTooLarge
	}
	if err := checkDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	// Any second value, including a bare token, is trailing data.
	if _, err := dec.Token(); err != io.EOF {
		return ErrTrailingData
	}
	return nil
}

// MaxNestingDepth bounds the nesting of objects and arrays in a document.
// The contract is three levels deep; anything deeper is hostile input and is
// rejected before the walker spends CPU on it.
const MaxNestingDepth = 8

// ErrTooDeep is returned when a document nests deeper than MaxNestingDepth.
var ErrTooDeep = errors.New("document nesting exceeds maximum depth")

// checkDuplicateKeys walks the token stream and rejects any object with a
// repeated key. encoding/json silently keeps the last value, and different
// parsers disagree, which makes duplicate keys a classic validation-bypass
// vector. The walk is linear in the document size: the depth is capped and
// the diagnostic path is only rendered when an error is returned.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrNotAnObject
	}
	w := &walker{dec: dec, path: []string{"$"}}
	return w.object()
}

type walker struct {
	dec  *json.Decoder
	path []string
}

func (w *walker) where() string { return strings.Join(w.path, "") }

func (w *walker) push(seg string) error {
	if len(w.path) > MaxNestingDepth {
		return fmt.Errorf("%w: at %s", ErrTooDeep, w.where())
	}
	w.path = append(w.path, seg)
	return nil
}

func (w *walker) pop() { w.path = w.path[:len(w.path)-1] }

func (w *walker) object() error {
	seen := map[string]struct{}{}
	for {
		tok, err := w.dec.Token()
		if err != nil {
			return fmt.Errorf("decode document: %w", err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("decode document: unexpected token %v at %s", tok, w.where())
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: %q at %s", ErrDuplicateKey, key, w.where())
		}
		seen[key] = struct{}{}
		if err := w.push("." + key); err != nil {
			return err
		}
		if err := w.value(); err != nil {
			return err
		}
		w.pop()
	}
}

func (w *walker) array() error {
	for i := 0; ; i++ {
		if !w.dec.More() {
			tok, err := w.dec.Token()
			if err != nil {
				return fmt.Errorf("decode document: %w", err)
			}
			if d, ok := tok.(json.Delim); !ok || d != ']' {
				return fmt.Errorf("decode document: unexpected token %v at %s", tok, w.where())
			}
			return nil
		}
		if err := w.push("[" + strconv.Itoa(i) + "]"); err != nil {
			return err
		}
		if err := w.value(); err != nil {
			return err
		}
		w.pop()
	}
}

func (w *walker) value() error {
	tok, err := w.dec.Token()
	if err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			return w.object()
		case '[':
			return w.array()
		default:
			return fmt.Errorf("decode document: unexpected token %v at %s", tok, w.where())
		}
	}
	return nil
}
