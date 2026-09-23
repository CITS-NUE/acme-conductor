package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// MinRSABits is the smallest RSA modulus accepted from a JWK set.
const MinRSABits = 2048

// jwk is the subset of a JSON Web Key this package reads. Keys carry more
// members (x5c, x5t, issuer, ...); they are ignored, not rejected: a
// provider's key set is not a document this project controls.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// signingKey is a published key with the algorithm, if any, the issuer
// published it for. A token verified with the key must name that
// algorithm: the header cannot pick another one the key type happens to
// support (an RSA key published for RS256 does not verify PS256).
type signingKey struct {
	key crypto.PublicKey
	alg string
}

// parseJWKS turns a JWK set document into the signing keys this package
// can use, indexed by key id. Keys of other types, without a key id,
// marked for a use other than signing, or published for an algorithm
// this package does not accept are skipped; a key that claims a usable
// type but is malformed, or whose declared algorithm does not fit its
// type, is an error, since a set with such a key cannot be trusted to be
// what the issuer published.
func parseJWKS(data []byte) (map[string]signingKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("key set is not valid JSON: %w", err)
	}
	if len(set.Keys) > MaxKeys {
		return nil, fmt.Errorf("key set has %d keys, more than %d", len(set.Keys), MaxKeys)
	}
	out := map[string]signingKey{}
	for i, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		var (
			key crypto.PublicKey
			err error
		)
		switch k.Kty {
		case "RSA":
			if k.Alg != "" && k.Alg != algRS256 && k.Alg != algPS256 {
				if k.Alg == algES256 {
					return nil, fmt.Errorf("key %d: RSA key published for %s", i, k.Alg)
				}
				continue
			}
			key, err = rsaKey(k)
		case "EC":
			if k.Alg != "" && k.Alg != algES256 {
				if k.Alg == algRS256 || k.Alg == algPS256 {
					return nil, fmt.Errorf("key %d: EC key published for %s", i, k.Alg)
				}
				continue
			}
			key, err = ecKey(k)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("key %d: key id %q appears twice", i, k.Kid)
		}
		out[k.Kid] = signingKey{key: key, alg: k.Alg}
	}
	if len(out) == 0 {
		return nil, errors.New("key set contains no usable signing key")
	}
	return out, nil
}

func rsaKey(k jwk) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil || len(n) == 0 {
		return nil, errors.New("RSA modulus is not base64url")
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("RSA exponent is not base64url of at most 4 bytes")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("RSA modulus has %d bits, fewer than %d", pub.N.BitLen(), MinRSABits)
	}
	if pub.E < 3 || pub.E%2 == 0 {
		return nil, errors.New("RSA exponent is not an odd integer of at least 3")
	}
	return pub, nil
}

func ecKey(k jwk) (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("EC curve %q is not P-256", k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) != 32 {
		return nil, errors.New("EC x is not 32 base64url bytes")
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(y) != 32 {
		return nil, errors.New("EC y is not 32 base64url bytes")
	}
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, errors.New("EC point is not on P-256")
	}
	return pub, nil
}
