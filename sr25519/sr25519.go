package sr25519

import (
	"crypto/sha512"

	sr "github.com/ChainSafe/go-schnorrkel"
	r255 "github.com/gtank/ristretto255"
)

func SharedSecret(pub, priv []byte) ([]byte, error) {

	pre := &r255.Element{}
	err := pre.Decode(pub)
	if err != nil {
		return nil, err
	}

	sc := &r255.Scalar{}
	err = sc.Decode(expandKey(priv))
	if err != nil {
		return nil, err
	}

	e := r255.Element{}
	secret := e.ScalarMult(sc, pre).Encode([]byte{})
	return secret, nil
}

// expandKey expands a secret key using ed25519-style bit clamping
// https://ristretto.group/formulas/decoding.html
// https://github.com/w3f/schnorrkel/blob/43f7fc00724edd1ef53d5ae13d82d240ed6202d5/src/keys.rs#L196
func expandKey(key []byte) []byte {
	newKey := [32]byte{}
	h := sha512.Sum512(key)
	copy(newKey[:], h[:32])
	newKey[0] &= 248
	newKey[31] &= 63
	newKey[31] |= 64
	l := len(newKey) - 1
	low := byte(0)
	for i := range newKey {
		r := newKey[l-i] & 0x07
		newKey[l-i] >>= 3
		newKey[l-i] += low
		low = r << 5
	}
	return newKey[:]
}

func GenerateKeyPair() ([]byte, []byte, error) {
	epk, err := sr.GenerateMiniSecretKey()
	if err != nil {
		return nil, nil, err
	}
	epke := epk.Encode()
	epkb := expandKey(epke[:])
	scp := &r255.Scalar{}
	err = scp.Decode(epkb)
	if err != nil {
		return nil, nil, err
	}

	ek := r255.NewElement()
	epub := ek.ScalarBaseMult(scp)
	epubb := epub.Encode([]byte{})
	return epke[:], epubb, nil
}
