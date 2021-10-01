package crypto_test

import (
	"context"
	"testing"

	"go.impervaunity.io/pkg/toolbox/crypto"
)

func TestRandomEncrypt(t *testing.T) {
	ctx := context.TODO()

	ciphertext, err := crypto.EncryptString("test_string", "", ctx)
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ciphertext, "", ctx)
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}

func TestEncrypt(t *testing.T) {
	ctx := context.TODO()

	ciphertext, err := crypto.EncryptString("test_string", "some_key", ctx)
	if err != nil {
		t.Errorf("error while encrypting string: %s", err.Error())
	}

	plaintext, err := crypto.DecryptString(ciphertext, "some_key", ctx)
	if err != nil {
		t.Errorf("error while decrypting string: %s", err.Error())
	}
	if plaintext != "test_string" {
		t.Errorf("want: test_string, got: %s", plaintext)
	}
}
