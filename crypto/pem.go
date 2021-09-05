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
// The following errors are returned by this function:
// ErrReadFileFailure
func DecodePEMBlockFromFile(file string, ctx context.Context) (*pem.Block, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("file", file).Logger()

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		e := &ErrReadFileFailure{Err: err, File: file}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		e := &ErrReadFileFailure{Err: errors.New("no PEM data was decoded"), File: file}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
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
// The following errors are returned by this function:
// ErrDecryptFailure
func DecryptPEMBlock(b *pem.Block, password []byte, ctx context.Context) ([]byte, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if b == nil {
		e := &ErrDecryptFailure{Err: errors.New("PEM block is nil")}
		logger.Error().Err(e.Err).Msg(e.Err.Error())
		return nil, e
	}

	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		e := &ErrDecryptFailure{Err: errors.New("no DEK-Info header in block")}
		logger.Error().Err(e.Err).Msg(e.Err.Error())
		return nil, e
	}

	idx := strings.Index(dek, ",")
	if idx == -1 {
		e := &ErrDecryptFailure{Err: errors.New("malformed DEK-Info header")}
		logger.Error().Err(e.Err).Msg(e.Err.Error())
		return nil, e
	}

	mode, hexIV := dek[:idx], dek[idx+1:]
	ciph := cipherByName(mode)
	if ciph == nil {
		e := &ErrDecryptFailure{Err: errors.New("unknown encryption mode")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		e := &ErrDecryptFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	if len(iv) != ciph.blockSize {
		e := &ErrDecryptFailure{Err: errors.New("incorrect IV size")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	// based on the OpenSSL implementation - the salt is the first 8 bytes of the initialization vector
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		e := &ErrDecryptFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	if len(b.Bytes)%block.BlockSize() != 0 {
		e := &ErrDecryptFailure{Err: errors.New("encrypted PEM data is not a multiple of the block size")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
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
		e := &ErrDecryptFailure{Err: errors.New("invalid padding")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	last := int(data[dlen-1])
	if dlen < last {
		e := &ErrDecryptFailure{Err: errors.New("password is incorrect")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	if last == 0 || last > ciph.blockSize {
		e := &ErrDecryptFailure{Err: errors.New("password is incorrect")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	for _, val := range data[dlen-last:] {
		if int(val) != last {
			e := &ErrDecryptFailure{Err: errors.New("password is incorrect")}
			logger.Error().Err(e.Err).Msg(e.Error())
			return nil, e
		}
	}
	return data[:dlen-last], nil
}

// EncryptPEMBlock returns a PEM block of the specified type holding the given DER encoded data encrypted with the
// specified algorithm and password according to RFC 1423.
//
// The following errors are returned by this function:
// ErrEncryptFailure, ErrGenerateIVFailure
func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg PEMCipher, ctx context.Context) (
	*pem.Block, error) {

	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	ciph := cipherByKey(alg)
	if ciph == nil {
		e := &ErrEncryptFailure{Err: errors.New("unknown encryption mode")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		e := &ErrGenerateIVFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	// the salt is the first 8 bytes of the initialization vector, matching the key derivation in DecryptPEMBlock.
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		e := &ErrEncryptFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
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
// The following errors are returned by this function:
// ErrDecryptFailure, ErrDecodeFailure, ErrParseCertificateFailure
func ParsePEMCertificateBytes(contents []byte, ctx context.Context) ([]*x509.Certificate, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if contents == nil {
		e := &ErrDecryptFailure{Err: errors.New("no content was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		e := &ErrDecodeFailure{Err: errors.New("no PEM data was decoded")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		e := &ErrParseCertificateFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return certs, nil
}

// ParsePEMCertificateFile takes a PEM-formatted file and converts it into one or more X509 certificates.
//
// The following errors are returned by this function:
// ErrReadFileFailure, any error returned by ParsePEMCertificateBytes
func ParsePEMCertificateFile(file string, ctx context.Context) ([]*x509.Certificate, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("file", file).Logger()

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		e := &ErrReadFileFailure{Err: err, File: file}
		logger.Error().Err(e.Err).Msg(err.Error())
		return nil, e
	}
	return ParsePEMCertificateBytes(contents, ctx)
}

// ParsePEMPrivateKeyBytes takes a PEM-formatted byte string and converts it into an RSA private key.
//
// If the private key is encrypted, be sure to include a password or else this function will return an error.
// If no password is required, you can safely pass nil for the password.
//
// The following errors are returned by this function:
// ErrDecryptFailure, ErrDecodeFailure
func ParsePEMPrivateKeyBytes(contents []byte, password []byte, ctx context.Context) (*rsa.PrivateKey, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	if contents == nil {
		e := &ErrDecryptFailure{Err: errors.New("no content was provided")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		e := &ErrDecodeFailure{Err: errors.New("no PEM data was decoded")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}

	var err error
	decryptedBlock := block.Bytes
	if IsEncryptedPEMBlock(block) {
		if password == nil {
			e := &ErrDecryptFailure{Err: errors.New("private key is encrypted but no password was supplied")}
			logger.Error().Err(e.Err).Msg(e.Error())
			return nil, e
		}
		decryptedBlock, err = DecryptPEMBlock(block, password, ctx)
		if err != nil {
			e := &ErrDecryptFailure{Err: err}
			logger.Error().Err(e.Err).Msg(e.Error())
			return nil, e
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(decryptedBlock)
	if err != nil {
		e := &ErrDecryptFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return key, nil
}

// ParsePEMPrivateKeyFile takes a PEM-formatted file and converts it into an RSA private key.
//
// If the private key is encrypted, be sure to include a password or else this function will return an error.
// If no password is required, you can safely pass nil for the password.
//
// The following errors are returned by this function:
// ErrReadFileFailure, any error returned by ParsePEMPrivateKeyBytes
func ParsePEMPrivateKeyFile(file string, password []byte, ctx context.Context) (*rsa.PrivateKey, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("file", file).Logger()

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		e := &ErrReadFileFailure{Err: err, File: file}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
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
