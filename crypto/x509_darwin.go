package crypto

import "crypto/x509"

// getSystemPool
func getSystemPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
