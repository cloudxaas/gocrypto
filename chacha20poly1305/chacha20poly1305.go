package fastencrypt

import (
	"io"
	
	"github.com/lukechampine/frand"
	"golang.org/x/crypto/chacha20poly1305"

)

// ChaCha20Poly1305Encrypt encrypts the given plaintext with the given key and nonce
// using the ChaCha20-Poly1305 AEAD cipher. The ciphertext is returned.
// The key length must be 32 bytes, and the nonce length must be 12 bytes.
func ChaCha20Poly1305Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Generate a random buffer for the ciphertext
	ciphertext := make([]byte, len(plaintext)+aead.Overhead())

	// Seal the plaintext with the given nonce
	return aead.Seal(ciphertext[:0], nonce, plaintext, nil), nil
}

// ChaCha20Poly1305Decrypt decrypts the given ciphertext with the given key and nonce
// using the ChaCha20-Poly1305 AEAD cipher. The plaintext is returned.
// The key length must be 32 bytes, and the nonce length must be 12 bytes.
func ChaCha20Poly1305Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext with the given nonce
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateNonce generates a random 12-byte nonce using the crypto/rand package.
func GenerateNonce() []byte {
	return frand.Bytes(12)
}
