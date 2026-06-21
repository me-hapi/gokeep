package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello world secret data")

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted data doesn't match original")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	plaintext := []byte("secret")

	encrypted, err := Encrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(key2, encrypted)
	if err != ErrDecrypt {
		t.Errorf("expected ErrDecrypt, got %v", err)
	}
}

func TestDifferentNoncesPerEncrypt(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same data")

	enc1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	enc2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	// Nonces should be different (first 12 bytes)
	nonce1 := enc1[:12]
	nonce2 := enc2[:12]

	if bytes.Equal(nonce1, nonce2) {
		t.Error("nonces should be different for each encryption")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	password := "testpassword"
	salt := []byte("1234567890123456") // 16 bytes

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("same password+salt should produce same key")
	}

	// Different password should produce different key
	key3 := DeriveKey("different", salt)
	if bytes.Equal(key1, key3) {
		t.Error("different passwords should produce different keys")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("short") // less than 12 bytes

	_, err := Decrypt(key, data)
	if err != ErrDecrypt {
		t.Errorf("expected ErrDecrypt for short data, got %v", err)
	}
}
