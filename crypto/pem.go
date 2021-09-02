package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"strings"

	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// PEMCipher is just an alias for int.
type PEMCipher int

// Possible values for the EncryptPEMBlock encryption algorithm.
const (
	_ PEMCipher = iota
	PEMCipherDES
	PEMCipher3DES
	PEMCipherAES128
	PEMCipherAES192
	PEMCipherAES256
)

// rfc1423Algos holds a slice of the possible ways to encrypt a PEM block. The ivSize numbers were taken from
// the OpenSSL source.
var rfc1423Algos = []rfc1423Algo{{
	cipher:     PEMCipherDES,
	name:       "DES-CBC",
	cipherFunc: des.NewCipher,
	keySize:    8,
	blockSize:  des.BlockSize,
}, {
	cipher:     PEMCipher3DES,
	name:       "DES-EDE3-CBC",
	cipherFunc: des.NewTripleDESCipher,
	keySize:    24,
	blockSize:  des.BlockSize,
}, {
	cipher:     PEMCipherAES128,
	name:       "AES-128-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    16,
	blockSize:  aes.BlockSize,
}, {
	cipher:     PEMCipherAES192,
	name:       "AES-192-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    24,
	blockSize:  aes.BlockSize,
}, {
	cipher:     PEMCipherAES256,
	name:       "AES-256-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    32,
	blockSize:  aes.BlockSize,
},
}

// DecodePEMBlockFromFile loads a file into memory and decodes any PEM data from it.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func DecodePEMBlockFromFile(file string, ctx context.Context) (*pem.Block, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to read file '%s': %s", file, err.Error())
		return nil, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		err := errors.New("no PEM data was decoded")
		logger.Error().Stack().Err(err).Msgf("Failed to decode PEM data: %s", err.Error())
		return nil, err
	}
	return block, nil
}

// DecryptPEMBlock takes a PEM block encrypted according to RFC 1423 and the password used to encrypt it and returns
// a slice of decrypted DER encoded bytes.
//
// It inspects the DEK-Info header to determine the algorithm used for decryption. If no DEK-Info header is present,
// an error is returned. If an incorrect password is detected an IncorrectPasswordError is returned. Because of
// deficiencies in the format, it's not always possible to detect an incorrect password. In these cases no error will
// be returned but the decrypted DER bytes will be random noise.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func DecryptPEMBlock(b *pem.Block, password []byte, ctx context.Context) ([]byte, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if b == nil {
		err := errors.New("PEM block is nil")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		err := errors.New("no DEK-Info header in block")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	idx := strings.Index(dek, ",")
	if idx == -1 {
		err := errors.New("malformed DEK-Info header")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	mode, hexIV := dek[:idx], dek[idx+1:]
	ciph := cipherByName(mode)
	if ciph == nil {
		err := errors.New("unknown encryption mode")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}
	if len(iv) != ciph.blockSize {
		err := errors.New("incorrect IV size")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	// based on the OpenSSL implementation - the salt is the first 8 bytes of the initialization vector
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	if len(b.Bytes)%block.BlockSize() != 0 {
		err := errors.New("encrypted PEM data is not a multiple of the block size")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	data := make([]byte, len(b.Bytes))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(data, b.Bytes)

	// blocks are padded using a scheme where the last n bytes of padding are all equal to n.
	// It can pad from 1 to blocksize bytes inclusive. See RFC 1423.
	// For example:
	//	[x y z 2 2]
	//	[x y 7 7 7 7 7 7 7]
	// If we detect a bad padding, we assume it is an invalid password.
	dlen := len(data)
	if dlen == 0 || dlen%ciph.blockSize != 0 {
		err := errors.New("invalid padding")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}
	last := int(data[dlen-1])
	if dlen < last {
		err := errors.New("password is incorrect")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}
	if last == 0 || last > ciph.blockSize {
		err := errors.New("password is incorrect")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}
	for _, val := range data[dlen-last:] {
		if int(val) != last {
			err := errors.New("password is incorrect")
			logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
			return nil, err
		}
	}
	return data[:dlen-last], nil
}

// EncryptPEMBlock returns a PEM block of the specified type holding the given DER encoded data encrypted with the
// specified algorithm and password according to RFC 1423.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg PEMCipher, ctx context.Context) (
	*pem.Block, error) {

	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	ciph := cipherByKey(alg)
	if ciph == nil {
		err := errors.New("unknown encryption mode")
		logger.Error().Stack().Err(err).Msgf("Failed to encrypt PEM data: %s", err.Error())
		return nil, err
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to generate IV: %s", err.Error())
		return nil, err
	}

	// the salt is the first 8 bytes of the initialization vector, matching the key derivation in DecryptPEMBlock.
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to encrypt PEM data: %s", err.Error())
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)

	// we could save this copy by encrypting all the whole blocks in the data separately, but it doesn't seem worth
	// the additional code
	copy(encrypted, data)
	// See RFC 1423, Section 1.1.
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}
	enc.CryptBlocks(encrypted, encrypted)

	return &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  ciph.name + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}, nil
}

// IsEncryptedPEMBlock returns whether the PEM block is password encrypted according to RFC 1423.
func IsEncryptedPEMBlock(b *pem.Block) bool {
	if b == nil {
		return false
	}
	_, ok := b.Headers["DEK-Info"]
	return ok
}

// ParsePEMCertificateBytes takes a PEM-formatted byte string and converts it into one or more X509 certificates.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func ParsePEMCertificateBytes(contents []byte, ctx context.Context) ([]*x509.Certificate, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if contents == nil {
		err := errors.New("no content was provided")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		err := errors.New("no PEM data was decoded")
		logger.Error().Stack().Err(err).Msgf("Failed to decode PEM data: %s", err.Error())
		return nil, err
	}

	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		logger.Error().Stack().Err(err).
			Msgf("Failed to parse PEM data into one or more certificates: %s", err.Error())
		return nil, err

	}
	return certs, nil
}

// ParsePEMCertificateFile takes a PEM-formatted file and converts it into one or more X509 certificates.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func ParsePEMCertificateFile(file string, ctx context.Context) ([]*x509.Certificate, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to read file '%s': %s", file, err.Error())
		return nil, err
	}
	return ParsePEMCertificateBytes(contents, ctx)
}

// ParsePEMPrivateKeyBytes takes a PEM-formatted byte string and converts it into an RSA private key.
//
// If the private key is encrypted, be sure to include a password or else this function will return an error.
// If no password is required, you can safely pass nil for the password.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func ParsePEMPrivateKeyBytes(contents []byte, password []byte, ctx context.Context) (*rsa.PrivateKey, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if contents == nil {
		err := errors.New("no content was provided")
		logger.Error().Stack().Err(err).Msgf("Failed to decrypt PEM data: %s", err.Error())
		return nil, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		err := errors.New("no PEM data was decoded")
		logger.Error().Stack().Err(err).Msgf("Failed to decode PEM data: %s", err.Error())
		return nil, err
	}

	var err error
	decryptedBlock := block.Bytes
	if IsEncryptedPEMBlock(block) {
		if password == nil {
			err := errors.New("private key is encrypted but no password was supplied")
			logger.Error().Stack().Err(err).Msgf("Failed to parse private key: %s", err.Error())
			return nil, err
		}
		decryptedBlock, err = DecryptPEMBlock(block, password, ctx)
		if err != nil {
			logger.Error().Stack().Err(err).Msgf("Failed to decrypt private key: %s", err.Error())
			return nil, err
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(decryptedBlock)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to parse private key: %s", err.Error())
		return nil, err
	}
	return key, nil
}

// ParsePEMPrivateKeyFile takes a PEM-formatted file and converts it into an RSA private key.
//
// If the private key is encrypted, be sure to include a password or else this function will return an error.
// If no password is required, you can safely pass nil for the password.
//
// Logging for this function is performed using either the zerolog logger supplied in the context or the
// global zerlog logger.
func ParsePEMPrivateKeyFile(file string, password []byte, ctx context.Context) (*rsa.PrivateKey, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		logger.Error().Stack().Err(err).Msgf("Failed to read file '%s': %s", file, err.Error())
		return nil, err
	}
	return ParsePEMPrivateKeyBytes(contents, password, ctx)
}

// rfc1423Algo holds a method for enciphering a PEM block.
type rfc1423Algo struct {
	cipher     PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
}

// cipherByKey returns an RFC1423 algorithm based on a PEM cipher key.
func cipherByKey(key PEMCipher) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.cipher == key {
			return alg
		}
	}
	return nil
}

// cipherByKey returns an RFC1423 algorithm based on a name.
func cipherByName(name string) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.name == name {
			return alg
		}
	}
	return nil
}

// deriveKey uses a key derivation function to stretch the password into a key with the number of bits our cipher
// requires.
//
// This algorithm was derived from the OpenSSL source.
func (c rfc1423Algo) deriveKey(password, salt []byte) []byte {
	hash := md5.New()
	out := make([]byte, c.keySize)
	var digest []byte

	for i := 0; i < len(out); i += len(digest) {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		hash.Write(salt)
		digest = hash.Sum(digest[:0])
		copy(out[i:], digest)
	}
	return out
}
