package registry

import (
	"crypto/rand"
	"sync"
	"time"
)

// crockford is the ULID alphabet: Crockford base32, upper case, no I, L, O
// or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID: 48 bits of Unix milliseconds followed by 80 random
// bits, rendered as 26 Crockford base32 characters. Identifiers contain
// only [0-9A-Z] and satisfy the contract's identifier rule (v1alpha1:
// ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$).
//
// Within one process identifiers are strictly monotonic: an id created in
// the same millisecond as the previous one (or after the clock stepped
// back) reuses that millisecond and increments the random part, as the
// ULID specification describes, so "ORDER BY id" is creation order for
// everything one Conductor writes.
func NewID() string {
	return NewIDAt(time.Now())
}

var (
	idMu     sync.Mutex
	idLastMS uint64
	idLast   [10]byte
)

// NewIDAt is NewID with an explicit timestamp; the monotonicity rule still
// applies against the last id this process generated.
func NewIDAt(t time.Time) string {
	ms := uint64(t.UnixMilli())
	idMu.Lock()
	defer idMu.Unlock()
	if ms <= idLastMS {
		ms = idLastMS
		if !increment(&idLast) {
			// The 80-bit random part overflowed (only possible after 2^80
			// ids in one millisecond, or a starting value of all ones):
			// move to the next millisecond with fresh randomness.
			ms++
			idLastMS = ms
			mustRand(idLast[:])
		}
	} else {
		idLastMS = ms
		mustRand(idLast[:])
	}
	var b [16]byte
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	copy(b[6:], idLast[:])
	return encodeULID(b)
}

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("registry: crypto/rand unavailable: " + err.Error())
	}
}

// increment adds one to a big-endian counter and reports false on overflow.
func increment(b *[10]byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

// encodeULID renders 128 bits as 26 base32 characters (the first character
// carries only 3 bits).
func encodeULID(b [16]byte) string {
	var out [26]byte
	out[0] = crockford[(b[0]&224)>>5]
	out[1] = crockford[b[0]&31]
	out[2] = crockford[(b[1]&248)>>3]
	out[3] = crockford[((b[1]&7)<<2)|((b[2]&192)>>6)]
	out[4] = crockford[(b[2]&62)>>1]
	out[5] = crockford[((b[2]&1)<<4)|((b[3]&240)>>4)]
	out[6] = crockford[((b[3]&15)<<1)|((b[4]&128)>>7)]
	out[7] = crockford[(b[4]&124)>>2]
	out[8] = crockford[((b[4]&3)<<3)|((b[5]&224)>>5)]
	out[9] = crockford[b[5]&31]
	out[10] = crockford[(b[6]&248)>>3]
	out[11] = crockford[((b[6]&7)<<2)|((b[7]&192)>>6)]
	out[12] = crockford[(b[7]&62)>>1]
	out[13] = crockford[((b[7]&1)<<4)|((b[8]&240)>>4)]
	out[14] = crockford[((b[8]&15)<<1)|((b[9]&128)>>7)]
	out[15] = crockford[(b[9]&124)>>2]
	out[16] = crockford[((b[9]&3)<<3)|((b[10]&224)>>5)]
	out[17] = crockford[b[10]&31]
	out[18] = crockford[(b[11]&248)>>3]
	out[19] = crockford[((b[11]&7)<<2)|((b[12]&192)>>6)]
	out[20] = crockford[(b[12]&62)>>1]
	out[21] = crockford[((b[12]&1)<<4)|((b[13]&240)>>4)]
	out[22] = crockford[((b[13]&15)<<1)|((b[14]&128)>>7)]
	out[23] = crockford[(b[14]&124)>>2]
	out[24] = crockford[((b[14]&3)<<3)|((b[15]&224)>>5)]
	out[25] = crockford[b[15]&31]
	return string(out[:])
}
