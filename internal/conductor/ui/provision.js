// Client-side sealing for encrypted EAB provisioning (issue #42).
//
// This file implements, byte-exact, the scheme documented at the top of
// pkg/api/v1alpha1/provisioning.go: an ACME External Account Binding
// (kid + hmac) is sealed to the Runner's X25519 provisioning public key
// with WebCrypto, entirely in this tab. Neither the Conductor nor this
// script's caller (app.js) ever holds the plaintext for longer than the
// call below needs it; the caller is responsible for clearing the form
// fields it read the kid/hmac from.
//
// Exposes one global: acmeConductorSealEAB(keyInfo, binding, generation,
// kid, hmac) -> Promise<payload>, where keyInfo is
// { publicKey (base64url, raw 32 bytes), keyId, version } as served by
// GET /api/v1alpha1/account-provisioning/key, and payload is the exact
// shape of v1alpha1.SealedProvisioning (the "encryptedCredential" body of
// POST .../provisioning). Also exposes acmeConductorX25519Supported(), a
// feature check the page runs before showing the provisioning form.
'use strict';

(() => {
  const HKDF_INFO = 'acme-conductor.cits-nue.github.io/v1alpha1 account-provisioning';

  function b64urlEncode(bytes) {
    let bin = '';
    for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(s) {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8(s) {
    return new TextEncoder().encode(s);
  }

  function concat(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }

  function provisioningAAD(version, keyId, binding, generation) {
    return utf8(
      'acme-conductor.cits-nue.github.io/v1alpha1\n' +
      'account-provisioning\n' +
      'version=' + version + '\n' +
      'keyId=' + keyId + '\n' +
      'binding=' + binding + '\n' +
      'generation=' + String(generation)
    );
  }

  // acmeConductorX25519Supported reports whether this browser's WebCrypto
  // implements X25519 key generation and bit derivation. Some browsers
  // (older Safari/Firefox releases) do not.
  async function acmeConductorX25519Supported() {
    if (!(window.crypto && window.crypto.subtle)) return false;
    try {
      const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      await crypto.subtle.exportKey('raw', pair.publicKey);
      return true;
    } catch (e) {
      return false;
    }
  }

  // acmeConductorSealEAB seals { kid, hmac } to keyInfo's Runner public
  // key, scoped to binding and generation. See provisioning.go for the
  // exact steps this mirrors.
  async function acmeConductorSealEAB(keyInfo, binding, generation, kid, hmac) {
    if (!(window.crypto && window.crypto.subtle)) {
      throw new Error('this browser has no WebCrypto support');
    }
    const runnerPubBytes = b64urlDecode(keyInfo.publicKey);
    if (runnerPubBytes.length !== 32) {
      throw new Error('runner public key must be 32 bytes');
    }
    const runnerPub = await crypto.subtle.importKey('raw', runnerPubBytes, { name: 'X25519' }, false, []);
    const ephPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const ephPubBytes = new Uint8Array(await crypto.subtle.exportKey('raw', ephPair.publicKey));
    const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: runnerPub }, ephPair.privateKey, 256);
    const salt = concat(ephPubBytes, runnerPubBytes);
    const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: utf8(HKDF_INFO) },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = provisioningAAD(keyInfo.version, keyInfo.keyId, binding, generation);
    // The plaintext's field order (kid, then hmac) and lack of whitespace
    // must match encoding/json's Marshal of provisioningPlaintext exactly
    // (see pkg/api/v1alpha1/testdata/provisioning/vector.json).
    const plaintext = utf8('{"kid":' + JSON.stringify(kid) + ',"hmac":' + JSON.stringify(hmac) + '}');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, aesKey, plaintext);
    return {
      version: keyInfo.version,
      keyId: keyInfo.keyId,
      ephemeralPublicKey: b64urlEncode(ephPubBytes),
      nonce: b64urlEncode(nonce),
      ciphertext: b64urlEncode(ciphertext),
    };
  }

  window.acmeConductorSealEAB = acmeConductorSealEAB;
  window.acmeConductorX25519Supported = acmeConductorX25519Supported;
})();
