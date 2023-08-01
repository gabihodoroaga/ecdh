package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

func SharedSecret(pub, priv []byte) ([]byte, error) {

	pkPriv := ed25519.PrivateKey(priv)
	xPriv := ed25519PrivateKeyToCurve25519(pkPriv)

	xPub, err := ed25519PublicKeyToCurve25519(pub)
	if err != nil {
		return nil, err
	}

	secret, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// ed25519PrivateKeyToCurve25519 converts a ed25519 private key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/980763a16e30ea5c285c271344d2202fcb18c33b/agessh/agessh.go#L287
func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

// ed25519PublicKeyToCurve25519 converts a ed25519 public key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/main/agessh/agessh.go#L190
func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}
