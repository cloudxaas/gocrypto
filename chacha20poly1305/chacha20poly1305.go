package fastencrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
        "golang.org/x/crypto/chacha20poly1305"

)

// ChaCha20Poly1305Encrypt encrypts the given plaintext with the given key and nonce
// using the ChaCha20-Poly1305 AEAD cipher. The ciphertext is returned.
// The key length must be 32 bytes, and the nonce length must be 12 bytes.
func ChaCha20Poly1305Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := cipher.NewChaCha20Poly1305(key)
	if err != nil {
		return nil, err
	}

	// Generate a random buffer for the ciphertext
	ciphertext := make([]byte, len(plaintext)+block.Overhead())

	// Seal the plaintext with the given nonce
	return block.Seal(ciphertext[:0], nonce, plaintext, nil), nil
}

// ChaCha20Poly1305Decrypt decrypts the given ciphertext with the given key and nonce
// using the ChaCha20-Poly1305 AEAD cipher. The plaintext is returned.
// The key length must be 32 bytes, and the nonce length must be 12 bytes.
func ChaCha20Poly1305Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := cipher.NewChaCha20Poly1305(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext with the given nonce
	plaintext, err := block.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateNonce generates a random 12-byte nonce using the crypto/rand package.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
