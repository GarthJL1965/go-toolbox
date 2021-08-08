package crypto_test

import (
	"testing"

	"go.imperva.dev/toolbox/crypto"
)

func TestRandomEncrypt(t *testing.T) {
	ciphertext, err := crypto.EncryptString("test_string", "")
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ciphertext, "")
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}

func TestEncrypt(t *testing.T) {
	ciphertext, err := crypto.EncryptString("test_string", "some_key")
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ciphertext, "some_key")
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}
