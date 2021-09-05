package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"go.imperva.dev/zerolog"
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
//
// The following errors are returned by this function:
// ErrLoadCertificateFailure
func NewCertificatePool(emptyPool bool, ctx context.Context) (*CertificatePool, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if emptyPool {
		return &CertificatePool{
			CertPool: x509.NewCertPool(),
		}, nil
	}

	pool, err := getSystemPool()
	if err != nil {
		e := &ErrLoadCertificateFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return &CertificatePool{
		CertPool: pool,
	}, nil
}

// AddPEMCertificatesFromFile adds one or more PEM-formatted certificates from a file to the certificate pool.
//
// The following errors are returned by this function:
// ErrLoadCertificateFailure
func (p *CertificatePool) AddPEMCertificatesFromFile(file string, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		e := &ErrLoadCertificateFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}

	if !p.AppendCertsFromPEM([]byte(contents)) {
		e := &ErrLoadCertificateFailure{Err: errors.New("one or more PEM certificates werre not parsed")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
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
//
// The following errors are returned by this function:
// ErrInvalidCertificate
func ValidateCertificate(cert *x509.Certificate, roots *CertificatePool, intermediates *CertificatePool,
	keyUsages []x509.ExtKeyUsage, cn string, ctx context.Context) error {

	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if cert == nil {
		e := &ErrInvalidCertificate{Err: errors.New("no certificate was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
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
		e := &ErrInvalidCertificate{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}

	// verify the common name
	if cn != "" && cert.Subject.CommonName != cn {
		e := &ErrInvalidCertificate{CommonName: cert.Subject.CommonName, ExpectedCommonName: cn,
			Err: fmt.Errorf("CommonName '%s' does not match expected CN '%s'", cert.Subject.CommonName, cn)}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}
	return nil
}

// NewSelfSignedCertificateKeyPair creates a new self-signed certificate using the given template and returns the
// public certificate and private key, respectively, on success.
//
// The following errors are returned by this function:
//
func NewSelfSignedCertificateKeyPair(template *x509.Certificate, keyBits int, ctx context.Context) (
	[]byte, []byte, error) {

	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		e := &ErrGeneratePrivateKeyFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, nil, e
	}
	publicKey := &privateKey.PublicKey
	key := new(bytes.Buffer)
	if err := pem.Encode(key, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		e := &ErrEncodeFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, nil, e
	}

	// create a self-signed certificate
	var parent = template
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		e := &ErrGenerateCertificateFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, nil, e
	}
	cert := new(bytes.Buffer)
	if err := pem.Encode(cert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		e := &ErrEncodeFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, nil, e
	}

	return cert.Bytes(), key.Bytes(), nil
}
