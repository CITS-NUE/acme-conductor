package v1alpha1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// checkDuplicateKeys walks the token stream and rejects any object with a
// repeated key. encoding/json silently keeps the last value, and different
// parsers disagree, which makes duplicate keys a classic validation-bypass
// vector.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrNotAnObject
	}
	return walkObject(dec, "$")
}

func walkObject(dec *json.Decoder, path string) error {
	seen := map[string]struct{}{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("decode document: %w", err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("decode document: unexpected token %v at %s", tok, path)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: %q at %s", ErrDuplicateKey, key, path)
		}
		seen[key] = struct{}{}
		if err := walkValue(dec, path+"."+key); err != nil {
			return err
		}
	}
}

func walkArray(dec *json.Decoder, path string) error {
	for i := 0; ; i++ {
		if !dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("decode document: %w", err)
			}
			if d, ok := tok.(json.Delim); !ok || d != ']' {
				return fmt.Errorf("decode document: unexpected token %v at %s", tok, path)
			}
			return nil
		}
		if err := walkValue(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
}

func walkValue(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			return walkObject(dec, path)
		case '[':
			return walkArray(dec, path)
		default:
			return fmt.Errorf("decode document: unexpected token %v at %s", tok, path)
		}
	}
	return nil
}
