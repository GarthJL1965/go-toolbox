package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"go.imperva.dev/zerolog/log"
)

// ParsePublicKeyFromCertificate parses the RSA public key portion from an X509 certificate.
func ParsePublicKeyFromCertificate(cert *x509.Certificate) (*rsa.PublicKey, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	// validate paramaters
	if cert == nil {
		err := errors.New("no certificate was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to extract public key: %s", err.Error())
		return nil, err
	}

	// extract the RSA public key from the certificate
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err := errors.New("public key does not appear to be in RSA format")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to extract public key: %s", err.Error())
		return nil, err
	}
	return publicKey, nil
}

// Sign takes the content and generates a signature using a private key certificate.
//
// Use the DecodePEMData() function to convert a PEM-formatted certificate into a PEM block. If the
// private key is encrypted, use the DecryptPEMBlock() function to decrypt it first.
//
// Use the Verify() function to verify the signature produced for the content.
func Sign(contents []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	// validate parameters
	if contents == nil {
		err := errors.New("no content was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to generate signature for contents: %s", err.Error())
		return nil, err
	}
	if privateKey == nil {
		err := errors.New("no private key was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to generate signature for contents: %s", err.Error())
		return nil, err
	}

	// hash the contents so we can sign that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// use PSS to sign the contents as it is newer and supposedly better than PKCSv1.5
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashSum, nil)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to generate signature for contents: %s", err.Error())
		return nil, err
	}
	log.Debug().Msg("successfully generated signature for content")
	return signature, nil
}

// Verify validates that the given contents have not been altered by checking them against the signature and
// public key provided.
//
// Use the Sign() function to create the signature used by this function to ensure the same hashing algorithm
// is applied.
func Verify(contents, signature []byte, publicKey *rsa.PublicKey) error {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	// validate parameters
	if contents == nil {
		err := errors.New("no content was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to verify signature for contents: %s", err.Error())
		return err
	}
	if signature == nil {
		err := errors.New("no signature was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to verify signature for contents: %s", err.Error())
		return err
	}
	if publicKey == nil {
		err := errors.New("no public key was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to verify signature for contents: %s", err.Error())
		return err
	}

	// hash the contents so we can verify that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// verify the signature
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashSum, signature, nil); err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to verify signature for contents: %s", err.Error())
		return err
	}
	return nil
}
