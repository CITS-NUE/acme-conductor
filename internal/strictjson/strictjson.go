// Package strictjson decodes JSON documents that carry security-relevant
// configuration or contracts: unknown fields, duplicate object keys,
// trailing data, non-object top levels and excessive nesting are all
// rejected. encoding/json alone keeps the last value of a duplicated key
// and different parsers disagree about it, which is a classic
// validation-bypass vector.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxNestingDepth bounds the nesting of objects and arrays. Every document
// this project decodes is a few levels deep; anything deeper is hostile
// input and is rejected before any CPU is spent walking it.
const MaxNestingDepth = 8

// Errors.
var (
	ErrTrailingData = errors.New("unexpected data after JSON document")
	ErrDuplicateKey = errors.New("duplicate object key")
	ErrNotAnObject  = errors.New("document is not a JSON object")
	ErrTooDeep      = errors.New("document nesting exceeds maximum depth")
)

// Unmarshal decodes data into v with all strict checks applied. The caller
// is responsible for bounding len(data).
func Unmarshal(data []byte, v any) error {
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

// checkDuplicateKeys walks the token stream and rejects any object with a
// repeated key. The walk is linear in the document size: the depth is
// capped and the diagnostic path is only rendered when an error is
// returned.
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
