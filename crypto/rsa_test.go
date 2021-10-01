package crypto_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"go.imperva.dev/zerolog"
	"go.impervaunity.io/toolbox/crypto"
)

const (
	TestContents = "This is a test message that should never be altered!"
	SigningKey   = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsYzgQZm1jyTHUuS2tvpvnlLFIDb1gc2L1jEPlQR6HoPhYNK8
jplMzBY/mYz7YML6JlgMUToemNomxjxT0Z56V9j7HT3C6gyenSE7U2BdzcWkcqyk
nFlbTdNTn8jjNMnURamK1C/JhakeoK+1ZrtI3rXCcudXiTg0ttR+BdnzWvhFKqT3
25y8dElMg4yoYiLIslF0q9fpjlRfnuEIxYmnITjoJr4j6qUNI8DxztIJ/boboaKS
Cdceh2K+2HrulywSYvJ98V35aJHA/UUvUGhtmgIlr8+/PFMnQj7eKz1+Y5Hw03ZS
E+49VMLnhBxPIRr2khzXBM4+PPVT0A2V/Tpv0QIDAQABAoIBAGLOShJXrtEdH4uC
2ieT0L/jwe2+h/uXXoVxQgGkvyzyKV9Phz04FKPSkcwqx82+U6U5BInDdTmM1V0m
P2L89YqjpoNMVocXRMGet7wbebhEj9J9PxH/LC9wNi5Khh5fXzDxO9//Q/+M8Q1t
Gt8zxEakEbUOBwnG7Jb+Q6+P7bymVN/ceffOdPlxZEb/rJ8YZXjYrjillj+jERLe
tVzm74kGjagbQzzmn+Ulj9X/ftXkSTVsJ7WaoJld6xOo92Gr5d4hSQyu9kq2/Etx
26oIiLILYgLmV7KhWygW2TkfpqseMks4/+iEKZjmkKAvQlkf2tXE5sUkmx1Z9N+4
zVqiIhECgYEA6T7rl+0bTo+YfEEUivucLA3LZhIICkjYKpB5lzz5CW18/LwBmOAi
JpHf4XycBEDtPqw072WksUwMmsvmulqMH6c24cgIc6M2kjTo7ndppZ15loC1NwE/
OgdqE3hvh/mbzHFQQqvdU2+Q0nd3tu7H+ppUbiW9CKChUf3hwhu5lmUCgYEAwt8E
SuvFqH2uJCFWq7CZoVDYhqnKCjTueBOmJSGh1MvxYz0FQN4ClS0Jexn4YyeBpNPd
1mc5pemX6IdU6wAPfqX6ooOdrIFr86Rp4IB3fI9uqjEzLf28azrNmEd5Qy2nH40a
xbNThM2he0B1xa+RUp3RkrLrnMQnr5JFHhmBtv0CgYBEdCTsp7fV7KrR/L+ssn95
JmtFf5FAg3R9uX0V990W+T0vZ3YIie875qAQK2QWk3+NXzkB8ZDOQAWLAMCsfJqX
R5oB1ZU1avc/HawnIICvDHJ8yzVj+Ue3HinxoO0KuSUScUce6hXAwQN94XYPCDFE
yTpyQT0jZREzYRF6yGxFSQKBgCb9qoU3Iahx5TsTdJ0Ly+GMJJblOCjMqH5cKB07
2n6Sg+0AU6HECi5BAamg66MjT3xka/mvU8iPsbZ0BZizvWXw3fJQdWcDyk7Iseqa
qc3BgToKeBwWrfGipWp3upqncs4MVLQECo0C+/GGV0pDs8cdDsbUh/IpCWvGz4+T
OPIdAoGBAMWbS7ZZIqzQtpZFVZdMZwQH6aJ/fIuoGC7yr58u48qdxwk/vTSK995A
BhdfzoIpRJAcH9g7iaQhx4tkpiC0W5CJPx4K+j17UVOuUfRrOyEUdQxAkIPK7mfx
DXjZYgp9TPbiobxURWY/+9Lg3q1Oq2e1D06GWYNjHN04DHJXaW80
-----END RSA PRIVATE KEY-----`
	SigningCertificate = `-----BEGIN CERTIFICATE-----
MIIEbTCCAlWgAwIBAgIIZD6QoGT0h5kwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTYW4gTWF0ZW8x
FDASBgNVBAoTC0ltcGVydmEgSW5jMR4wHAYDVQQLExVJbXBlcnZhIFVuaXR5IFBy
b2plY3QxJjAkBgNVBAMTHUltcGVydmEgVW5pdHkgQ29kZSBTaWduaW5nIENBMB4X
DTIxMDYyODAwMDAwMFoXDTMxMTIzMTIzNTk1OVowMjEwMC4GA1UEAxMnQ3J5cHRv
IFBhY2thZ2UgVGVzdCBTaWduaW5nIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAsYzgQZm1jyTHUuS2tvpvnlLFIDb1gc2L1jEPlQR6
HoPhYNK8jplMzBY/mYz7YML6JlgMUToemNomxjxT0Z56V9j7HT3C6gyenSE7U2Bd
zcWkcqyknFlbTdNTn8jjNMnURamK1C/JhakeoK+1ZrtI3rXCcudXiTg0ttR+Bdnz
WvhFKqT325y8dElMg4yoYiLIslF0q9fpjlRfnuEIxYmnITjoJr4j6qUNI8DxztIJ
/boboaKSCdceh2K+2HrulywSYvJ98V35aJHA/UUvUGhtmgIlr8+/PFMnQj7eKz1+
Y5Hw03ZSE+49VMLnhBxPIRr2khzXBM4+PPVT0A2V/Tpv0QIDAQABoyQwIjALBgNV
HQ8EBAMCA4gwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggIB
ABzOvY1UVuUeQRRoEyn3IZKeTiimNaErF5aagosTsD1BOeLcWOS2DhbLMiglmG40
LUlYx9qlKpCeBaOYQAcdYyiL5jrjK+E2pRX7YtQpJexVDzaxB9zSVyOkw9ZckV+N
uJd36BzCbb60UhGV8F65T2yk3Vp7QDUHL7vHd7ukiRH0BFvJRs9bWy702rq0jebM
fps/TbfHHvSXj7+2x3TN6QH99KfmZjknQuwtOaWdOXFWxYFnhWqAfS5bbt5SHp8e
tFLP8yjBEcbN7wKA2091J6cHg6bgvuGEJIiP6NBNvJbE3he7iazpI1fXgFMOccgc
i3yKEeAFbJX/p+oEzIopiuok2eaj63bHB0eXS3+hZoQ4dQg/pd1d7IArFP5gGun7
efNmtBDU9QDMZhg/fRnfI+Uw0lMJGLpEKeMNFlvr6UGn75y0IrRRkAt6ZYzAprTV
NdNEtHY5Iem+ihuAU53EkwwGc5nmQnXRhEtwbXK3rIWNAdq2XJWc84OZ0CKAM58X
iiwJwx5X1lnPsfH37+7QGZg7p8xTqa8phuzVsGkV2L4MmunYUcQZSDrBnItGj3t5
nGqz0wbpjznmKRkgTUozdv3ERoIT1P2f8ZwhhyXSSGAB29cTrezSFdj6qgq1OeNk
C+tcrjo+xjaA+wZTimyQZb+yYT/kPQPEDvdvUE5QoKUX
-----END CERTIFICATE-----`
)

func TestParsePublicKeyFromCertificateFailure(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.TODO()

	t.Log("*** testing nil certificate ***")
	expected := "failed to extract public key from certificate: no certificate was provided"
	_, err := crypto.ParsePublicKeyFromCertificate(nil, ctx)
	if err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing invalid public key format ***")
	expected = "failed to extract public key from certificate: public key does not appear to be in RSA format"
	_, err = crypto.ParsePublicKeyFromCertificate(&x509.Certificate{}, ctx)
	if err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}
}

func TestSignFailure(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.TODO()

	t.Log("*** testing nil contents ***")
	expected := "failed to generate signature for data: no content was provided"
	_, err := crypto.Sign(nil, nil, ctx)
	if err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got '%s', expected '%s'", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing nil private key ***")
	expected = "failed to generate signature for data: no private key was provided"
	_, err = crypto.Sign([]byte(TestContents), nil, ctx)
	if err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing invalid private key ***")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error: failed to generate random private key")
	}
	privateKey.D = big.NewInt(1024)
	privateKey.PublicKey.E = 12
	_, err = crypto.Sign([]byte(TestContents), privateKey, ctx)
	if err == nil {
		t.Errorf("error: got nil, expected error")
	} else {
		t.Log("success")
	}
}

func TestSignVerifyFailure(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.TODO()
	t.Log("** testing sign/verify failure ***")

	// generate a random private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error: failed to generate random private key")
	}

	// parse the public key
	block, _ := pem.Decode([]byte(SigningCertificate))
	if block == nil {
		t.Fatal("error: No PEM data was decoded.")
	} else {
		t.Log("  decoded PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error: failed to parse public key: %s", err.Error())
	} else {
		t.Log("  parsed PKCS1 public key from PEM block")
	}
	publicKey, err := crypto.ParsePublicKeyFromCertificate(cert, ctx)
	if err != nil {
		t.Fatalf("error: certificate does not appear to be an RSA public key")
	} else {
		t.Log("  extracted public key")
	}

	// sign the contents
	signature, err := crypto.Sign([]byte(TestContents), privateKey, ctx)
	if err != nil {
		t.Fatalf("error: failed to generate signature: %s", err.Error())
	} else {
		t.Log("  generated signature")
	}

	// verify the signature
	if err := crypto.Verify([]byte(TestContents), signature, publicKey, ctx); err == nil {
		t.Fatalf("error: expected error, got nil")
	}
	t.Log("  signature verification failed as expected")
	t.Log("success")
}

func TestSignVerifySuccess(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	ctx := context.TODO()

	// parse the private key
	block, _ := pem.Decode([]byte(SigningKey))
	if block == nil {
		t.Fatal("error: No PEM data was decoded.")
	} else {
		t.Log("  decoded PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("error: failed to parse private key: %s", err.Error())
	} else {
		t.Log("  parsed PKCS1 private key from PEM block")
	}

	// parse the public key
	block, _ = pem.Decode([]byte(SigningCertificate))
	if block == nil {
		t.Fatal("error: No PEM data was decoded.")
	} else {
		t.Log("  decoded PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error: failed to parse public key: %s", err.Error())
	} else {
		t.Log("  parsed PKCS1 public key from PEM block")
	}
	publicKey, err := crypto.ParsePublicKeyFromCertificate(cert, ctx)
	if err != nil {
		t.Fatalf("error: certificate does not appear to be an RSA public key")
	} else {
		t.Log("  extracted public key")
	}

	// sign the contents
	signature, err := crypto.Sign([]byte(TestContents), key, ctx)
	if err != nil {
		t.Fatalf("error: failed to generate signature: %s", err.Error())
	} else {
		t.Log("  generated signature")
	}

	// verify the signature
	if err := crypto.Verify([]byte(TestContents), signature, publicKey, ctx); err != nil {
		t.Fatalf("error: failed to verify signature: %s", err.Error())
	}
	t.Log("  signature is verified")
	t.Log("success")
}

func TestVerifyFailure(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.TODO()

	t.Log("*** loading public key ***")
	block, _ := pem.Decode([]byte(SigningCertificate))
	if block == nil {
		t.Fatal("error: No PEM data was decoded.")
	} else {
		t.Log("  decoded PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error: failed to parse public key: %s", err.Error())
	} else {
		t.Log("  parsed PKCS1 public key from PEM block")
	}
	publicKey, err := crypto.ParsePublicKeyFromCertificate(cert, ctx)
	if err != nil {
		t.Fatalf("error: certificate does not appear to be an RSA public key")
	} else {
		t.Log("  extracted public key")
	}

	t.Log("*** testing nil contents ***")
	expected := "the signature for the data is invalid: no content was provided"
	if err := crypto.Verify(nil, nil, nil, ctx); err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing nil signature ***")
	expected = "the signature for the data is invalid: no signature was provided"
	if err := crypto.Verify([]byte(TestContents), nil, nil, ctx); err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing nil public key ***")
	expected = "the signature for the data is invalid: no public key was provided"
	if err := crypto.Verify([]byte(TestContents), []byte{}, nil, ctx); err == nil {
		t.Errorf("error: got nil, expected %s", expected)
	} else {
		errMsg := err.Error()
		if errMsg != expected {
			t.Errorf("error: got %s, expected %s", errMsg, expected)
		} else {
			t.Log("success")
		}
	}

	t.Log("*** testing invalid signature ***")
	if err := crypto.Verify([]byte(TestContents), []byte{}, publicKey, ctx); err == nil {
		t.Errorf("error: got nil, expected error")
	} else {
		t.Logf("success - error was %s", err.Error())
	}
}
