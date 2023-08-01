package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func RemovePadding(b []byte) ([]byte, error) {
	l := int(b[len(b)-1])
	if l > 16 {
		return nil, errors.New("padding incorrect")
	}

	return b[:len(b)-l], nil
}

// addPadding adds padding to a block of data
func AddPadding(b []byte) []byte {
	l := 16 - len(b)%16
	padding := make([]byte, l)
	padding[l-1] = byte(l)
	return append(b, padding...)
}

// DecryptCBC decrypt bytes using a key and IV with AES in CBC mode.
func DecryptCBC(data, iv, key []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	decryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(decryptedData, data)

	return
}

// EncryptCBC encrypt data using a key and IV with AES in CBC mode.
func EncryptCBC(data, iv, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	encryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedData, data)

	return
}

// MakeRandom is a helper that makes a new buffer full of random data.
func MakeRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}
