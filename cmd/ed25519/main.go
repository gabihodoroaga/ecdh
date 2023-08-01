// A simple tool capable of encrypting and decrypting a message using ed25519 keys
package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gabihodoroaga/ecdh/ed25519"
	"github.com/gabihodoroaga/ecdh/sym"
)

func main() {
	// flags -e, -d, -key -message

	encFlag := flag.Bool("e", false, "Encrypt a message using a ed25519 public key")
	decFlag := flag.Bool("d", false, "Decrypt a message using a ed25519 private key")
	keyFlag := flag.String("key", "", "For encrypt this is the public key, for decrypt this is the private key in hex format")
	messageFlag := flag.String("m", "", "The message to be encrypted. If the message starts with 0x it will be converted into bytes")
	flag.Parse()

	if (!*encFlag && !*decFlag) || (*encFlag && *decFlag) {
		flag.Usage()
		os.Exit(1)
	}

	keyBytes, ok := decodeHex(*keyFlag)
	if !ok {
		fmt.Printf("Invalid key provided")
		os.Exit(1)
	}

	var messageByes []byte
	if strings.HasPrefix(*messageFlag, "0x") {
		messageByes, ok = decodeHex(*messageFlag)
		if !ok {
			fmt.Printf("Invalid message bytes")
			os.Exit(1)
		}
	} else {
		messageByes = []byte(*messageFlag)
	}

	if *encFlag {
		enc, err := encrypt(keyBytes, messageByes)
		if err != nil {
			fmt.Printf("failed to encrypt: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("0x%s", hex.EncodeToString(enc))
	} else {
		dec, err := decrypt(keyBytes, messageByes)
		if err != nil {
			fmt.Printf("failed to decrypt: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("%s", string(dec))
	}
}

// encrypt using AES-128-CBC-HMAC-SHA1 scheme
func encrypt(key, msg []byte) ([]byte, error) {
	epkb, epubb, err := ed25519.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	secret, err := ed25519.SharedSecret(key, epkb)
	if err != nil {
		return nil, err

	}

	shared := sha256.Sum256(secret)
	iv, err := sym.MakeRandom(16)
	if err != nil {
		return nil, err
	}

	paddedIn := sym.AddPadding(msg)
	ct, err := sym.EncryptCBC(paddedIn, iv, shared[:16])
	if err != nil {
		return nil, err
	}

	out := make([]byte, 1+len(epubb)+16)
	out[0] = byte(len(epubb))
	copy(out[1:], epubb)
	copy(out[1+len(epubb):], iv)
	out = append(out, ct...)

	h := hmac.New(sha1.New, shared[16:])
	h.Write(iv)
	h.Write(ct)
	out = h.Sum(out)
	return out, nil
}

// decrypt using AES-128-CBC-HMAC-SHA1 scheme
func decrypt(key, msg []byte) ([]byte, error) {
	ephLen := int(msg[0])
	ephPub := msg[1 : 1+ephLen]
	ct := msg[1+ephLen:]
	if len(ct) < (sha1.Size + aes.BlockSize) {
		return nil, errors.New("invalid ciphertext")
	}

	secret, err := ed25519.SharedSecret(ephPub, key)
	if err != nil {
		return nil, err
	}

	shared := sha256.Sum256(secret)

	tagStart := len(ct) - sha1.Size
	h := hmac.New(sha1.New, shared[16:])
	h.Write(ct[:tagStart])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, ct[tagStart:]) {
		return nil, errors.New("invalid MAC")
	}

	paddedOut, err := sym.DecryptCBC(ct[aes.BlockSize:tagStart], ct[:aes.BlockSize], shared[:16])
	if err != nil {
		return nil, err
	}
	return sym.RemovePadding(paddedOut)
}

func decodeHex(v string) ([]byte, bool) {
	v = strings.TrimPrefix(v, "0x")
	res, err := hex.DecodeString(v)
	return res, err == nil
}
