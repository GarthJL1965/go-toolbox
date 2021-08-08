package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"go.imperva.dev/zerolog/log"
)

// CertificatePool stores X509 certificates.
type CertificatePool struct {
	*x509.CertPool
}

// NewCertificatePool creates a new CertificatePool object.
//
// If empty is true, return an empty certificate pool instead of a pool containing a copy of all of the system's
// trusted root certificates.
func NewCertificatePool(emptyPool bool) (*CertificatePool, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Bool("empty_pool", emptyPool).Logger())
	defer restoreLogger()

	if emptyPool {
		return &CertificatePool{
			CertPool: x509.NewCertPool(),
		}, nil
	}

	pool, err := getSystemPool()
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to load system certificates into pool: %s", err.Error())
		return nil, err
	}
	return &CertificatePool{
		CertPool: pool,
	}, nil
}

// AddPEMCertificatesFromFile adds one or more PEM-formatted certificates from a file to the certificate pool.
func (p *CertificatePool) AddPEMCertificatesFromFile(file string) error {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Str("certificate_file", file).Logger())
	defer restoreLogger()

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to load PEM certificates from file '%s': %s", file, err.Error())
		return err
	}

	if !p.AppendCertsFromPEM([]byte(contents)) {
		err := errors.New("one or more PEM certificates werre not parsed")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to load PEM certificates from file '%s': %s", file, err.Error())
		return err
	}
	return nil
}

// ValidateCertificate verifies the given certificate is completely trusted.
//
// If the certificate was signed with a key that is not trusted by the default system certificate pool, be sure
// to specify a root CA certificate pool and, if necessary, an intermediate pool containing the certificates
// required to verify the chain.
//
// If you wish to match against specific X509 extended key usages such as verifying the signing key has the
// Code Signing key usage, pass those fields in the keyUsages parameter.
//
// If you wish to verify the common name (CN) field of the public key passed in, specify a non-empty string
// for the cn parameter. This match is case-sensitive.
func ValidateCertificate(cert *x509.Certificate, roots *CertificatePool, intermediates *CertificatePool,
	keyUsages []x509.ExtKeyUsage, cn string) error {

	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	if cert == nil {
		err := errors.New("no certificate was provided")
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to validate certificate: %s", err.Error())
		return err
	}

	// verify the certificate chain and usage
	verifyOptions := x509.VerifyOptions{}
	if roots != nil {
		verifyOptions.Roots = roots.CertPool
	}
	if intermediates != nil {
		verifyOptions.Intermediates = intermediates.CertPool
	}
	if keyUsages != nil {
		verifyOptions.KeyUsages = keyUsages
	}
	if _, err := cert.Verify(verifyOptions); err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to validate certificate: %s", err.Error())
		return err
	}

	// verify the common name
	if cn != "" && cert.Subject.CommonName != cn {
		err := fmt.Errorf("CommonName '%s' does not match expected CN '%s'", cert.Subject.CommonName, cn)
		log.
			Error().Stack().
			Str("certificate_cn", cert.Subject.CommonName).
			Str("expected_cn", cn).
			Err(err).
			Msgf("failed to validate certificate: %s", err.Error())
		return err
	}
	log.Debug().Msg("certificate has been validated")
	return nil
}

// NewSelfSignedCertificateKeyPair creates a new self-signed certificate using the given template and returns the
// public certificate and private key, respectively, on success.
func NewSelfSignedCertificateKeyPair(template *x509.Certificate, keyBits int) ([]byte, []byte, error) {
	restoreLogger, _ := log.ReplaceGlobal(log.With().PackageCaller().Logger())
	defer restoreLogger()

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to generate private key: %s", err.Error())
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	key := new(bytes.Buffer)
	if err := pem.Encode(key, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to PEM-encode private key: %s", err.Error())
		return nil, nil, err
	}

	// create a self-signed certificate
	var parent = template
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to generate self-signed certificate: %s", err.Error())
		return nil, nil, err
	}
	cert := new(bytes.Buffer)
	if err := pem.Encode(cert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		log.
			Error().Stack().
			Err(err).
			Msgf("failed to PEM-encode certificate: %s", err.Error())
		return nil, nil, err
	}

	return cert.Bytes(), key.Bytes(), nil
}
