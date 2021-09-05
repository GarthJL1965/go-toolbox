package crypto

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// ParsePublicKeyFromCertificate parses the RSA public key portion from an X509 certificate.
//
// The following errors are returned by this function:
// ErrExtractPublicKeyFailure
func ParsePublicKeyFromCertificate(cert *x509.Certificate, ctx context.Context) (*rsa.PublicKey, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// validate paramaters
	if cert == nil {
		e := &ErrExtractPublicKeyFailure{Err: errors.New("no certificate was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	// extract the RSA public key from the certificate
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		e := &ErrExtractPublicKeyFailure{Err: errors.New("public key does not appear to be in RSA format")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return publicKey, nil
}

// Sign takes the content and generates a signature using a private key certificate.
//
// Use the DecodePEMData() function to convert a PEM-formatted certificate into a PEM block. If the
// private key is encrypted, use the DecryptPEMBlock() function to decrypt it first.
//
// Use the Verify() function to verify the signature produced for the content.
//
// The following errors are returned by this function:
// ErrSignDataFailure
func Sign(contents []byte, privateKey *rsa.PrivateKey, ctx context.Context) ([]byte, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// validate parameters
	if contents == nil {
		e := &ErrSignDataFailure{Err: errors.New("no content was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	if privateKey == nil {
		e := &ErrSignDataFailure{Err: errors.New("no private key was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	// hash the contents so we can sign that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// use PSS to sign the contents as it is newer and supposedly better than PKCSv1.5
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashSum, nil)
	if err != nil {
		e := &ErrSignDataFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return signature, nil
}

// Verify validates that the given contents have not been altered by checking them against the signature and
// public key provided.
//
// Use the Sign() function to create the signature used by this function to ensure the same hashing algorithm
// is applied.
//
// The following errors are returned by this function:
// ErrInvalidSignature
func Verify(contents, signature []byte, publicKey *rsa.PublicKey, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// validate parameters
	if contents == nil {
		e := &ErrInvalidSignature{Err: errors.New("no content was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}
	if signature == nil {
		e := &ErrInvalidSignature{Err: errors.New("no signature was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}
	if publicKey == nil {
		e := &ErrInvalidSignature{Err: errors.New("no public key was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}

	// hash the contents so we can verify that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// verify the signature
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashSum, signature, nil); err != nil {
		e := &ErrInvalidSignature{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}
	return nil
}
