package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Encrypt the plaintext secret using AES-256 with GCM-96.
func encryptaesgcm(masterpass, plaintext []byte) ([]byte, error) {
	keyLength := 2 * aes.BlockSize
	key := make([]byte, keyLength)
	if len(masterpass) >= keyLength {
		copy(key, masterpass[0:keyLength])
	} else {
		copy(key, masterpass)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	n, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	if n != len(nonce) {
		return nil, NewNonceGenerationError(errors.New("could not fill gcm nonce"))
	}

	// The ciphertext's first 12 bytes is the nonce and the next 32 bytes is
	// the cipher itself.
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func decryptaesgcm(masterpass, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterpass)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce from the ciphertext
	nonce := ciphertext[:12]

	return aesgcm.Open(nil, nonce, ciphertext[12:], nil)

}

func bytesTohex(data []byte) string {
	return fmt.Sprintf("%x", data)
}

func hexToBytes(h string) ([]byte, error) {
	data, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Encrypt the values of the map. The keys will not be encrypted. The encrypted
// values will be associated with their respective keys.
func encryptMap(masterpass []byte, secretList map[string]string) (map[string][]byte, error) {
	encryptedMap := make(map[string][]byte)
	for k, v := range secretList {
		cipher, err := encryptaesgcm(masterpass, []byte(v))
		if err != nil {
			return encryptedMap, err
		}

		encryptedMap[k] = cipher
	}

	return encryptedMap, nil
}
