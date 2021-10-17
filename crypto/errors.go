package crypto

import "fmt"

// Object error codes (1251-1500)
const (
	ErrDecodeFailureCode                     = 1251
	ErrGenerateCipherFailureCode             = 1252
	ErrGenerateGCMFailureCode                = 1253
	ErrDecryptFailureCode                    = 1254
	ErrGenerateRandomKeyFailureCode          = 1255
	ErrGenerateNonceFailureCode              = 1256
	ErrReadFileFailureCode                   = 1257
	ErrEncryptFailureCode                    = 1258
	ErrGenerateIVFailureCode                 = 1259
	ErrParseCertificateFailureCode           = 1260
	ErrGeneratePGPKeyFailureCode             = 1261
	ErrLockPGPKeyFailureCode                 = 1262
	ErrArmorPGPKeyFailureCode                = 1263
	ErrLoadPGPKeyFailureCode                 = 1264
	ErrUnlockPGPKeyFailureCode               = 1265
	ErrGetPGPKeyFailureCode                  = 1266
	ErrExtractPublicKeyFailureCode           = 1267
	ErrSignDataFailureCode                   = 1268
	ErrInvalidSignatureCode                  = 1269
	ErrLoadCertificateFailureCode            = 1270
	ErrInvalidCertificateCode                = 1271
	ErrGeneratePrivateKeyFailureCode         = 1272
	ErrGenerateCertificateFailureCode        = 1273
	ErrEncodeFailureCode                     = 1274
	ErrSignJWTTokenFailureCode               = 1275
	ErrInvalidJWTTokenSignatureAlgorithmCode = 1276
	ErrInvalidJWTTokenClaimsCode             = 1277
	ErrParseJWTTokenFailureCode              = 1278
)

// ErrDecodeFailure occurs when encoded data cannot be decoded.
type ErrDecodeFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrDecodeFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrDecodeFailure) Error() string {
	return fmt.Sprintf("failed to decode data: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrDecodeFailure) Code() int {
	return ErrDecodeFailureCode
}

// ErrGenerateCipherFailure occurs when creation of a new cipher fails.
type ErrGenerateCipherFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateCipherFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateCipherFailure) Error() string {
	return fmt.Sprintf("failed to generate cipher key block: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateCipherFailure) Code() int {
	return ErrGenerateCipherFailureCode
}

// ErrGenerateGCMFailure occurs when creation of a new GCM fails.
type ErrGenerateGCMFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateGCMFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateGCMFailure) Error() string {
	return fmt.Sprintf("failed to wrap block cipher in GCM: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateGCMFailure) Code() int {
	return ErrGenerateGCMFailureCode
}

// ErrDecryptFailure occurs when data cannot be decrypted.
type ErrDecryptFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrDecryptFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrDecryptFailure) Error() string {
	return fmt.Sprintf("failed to decrypt data: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrDecryptFailure) Code() int {
	return ErrDecryptFailureCode
}

// ErrGenerateRandomKeyFailure occurs when a random encryption key cannot be generated.
type ErrGenerateRandomKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateRandomKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateRandomKeyFailure) Error() string {
	return fmt.Sprintf("failed to generate random key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateRandomKeyFailure) Code() int {
	return ErrGenerateRandomKeyFailureCode
}

// ErrGenerateNonceFailure occurs when a nonce for encryption cannot be generated.
type ErrGenerateNonceFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateNonceFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateNonceFailure) Error() string {
	return fmt.Sprintf("failed to generate nonce: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateNonceFailure) Code() int {
	return ErrGenerateNonceFailureCode
}

// ErrReadFileFailure occurs when there is an error reading a file.
type ErrReadFileFailure struct {
	Err  error
	File string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrReadFileFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrReadFileFailure) Error() string {
	return fmt.Sprintf("failed to read file '%s': %s", e.File, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrReadFileFailure) Code() int {
	return ErrReadFileFailureCode
}

// ErrEncryptFailure occurs when data fails to be encrypted.
type ErrEncryptFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrEncryptFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrEncryptFailure) Error() string {
	return fmt.Sprintf("failed to encrypt data: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrEncryptFailure) Code() int {
	return ErrEncryptFailureCode
}

// ErrGenerateIVFailure occurs when an initialization vector cannot be generated.
type ErrGenerateIVFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateIVFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateIVFailure) Error() string {
	return fmt.Sprintf("failed to generate initialization vector: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateIVFailure) Code() int {
	return ErrGenerateIVFailureCode
}

// ErrParseCertificateFailure occurs when one or more certificates cannot be parsed
type ErrParseCertificateFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrParseCertificateFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrParseCertificateFailure) Error() string {
	return fmt.Sprintf("failed to parse PEM data into one or more certificates: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrParseCertificateFailure) Code() int {
	return ErrParseCertificateFailureCode
}

// ErrGeneratePGPKeyFailure occurs when a new PGP key cannot be generated.
type ErrGeneratePGPKeyFailure struct {
	Name    string
	Email   string
	KeyType string
	Bits    int
	Err     error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGeneratePGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGeneratePGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to generate PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGeneratePGPKeyFailure) Code() int {
	return ErrGeneratePGPKeyFailureCode
}

// ErrLockPGPKeyFailure occurs when a PGP key cannot be locked.
type ErrLockPGPKeyFailure struct {
	Name    string
	Email   string
	KeyType string
	Bits    int
	Err     error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrLockPGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrLockPGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to lock PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrLockPGPKeyFailure) Code() int {
	return ErrLockPGPKeyFailureCode
}

// ErrArmorPGPKeyFailure occurs when a PGP key cannot be wrapped in armor.
type ErrArmorPGPKeyFailure struct {
	Name    string
	Email   string
	KeyType string
	Bits    int
	Err     error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrArmorPGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrArmorPGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to armor PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrArmorPGPKeyFailure) Code() int {
	return ErrArmorPGPKeyFailureCode
}

// ErrLoadPGPKeyFailure occurs when a PGP key cannot be loaded.
type ErrLoadPGPKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrLoadPGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrLoadPGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to load PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrLoadPGPKeyFailure) Code() int {
	return ErrLoadPGPKeyFailureCode
}

// ErrUnlockPGPKeyFailure occurs when a PGP key cannot be unlocked.
type ErrUnlockPGPKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrUnlockPGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrUnlockPGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to unlock PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrUnlockPGPKeyFailure) Code() int {
	return ErrUnlockPGPKeyFailureCode
}

// ErrGetPGPKeyFailure occurs when a PGP key cannot be retrieved.
type ErrGetPGPKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGetPGPKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGetPGPKeyFailure) Error() string {
	return fmt.Sprintf("failed to retrieve PGP key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGetPGPKeyFailure) Code() int {
	return ErrGetPGPKeyFailureCode
}

// ErrExtractPublicKeyFailure occurs when the public key cannot be extracted from an X509 certificate.
type ErrExtractPublicKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrExtractPublicKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrExtractPublicKeyFailure) Error() string {
	return fmt.Sprintf("failed to extract public key from certificate: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrExtractPublicKeyFailure) Code() int {
	return ErrExtractPublicKeyFailureCode
}

// ErrSignDataFailure occurs when signing data with a private key fails.
type ErrSignDataFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrSignDataFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrSignDataFailure) Error() string {
	return fmt.Sprintf("failed to generate signature for data: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrSignDataFailure) Code() int {
	return ErrSignDataFailureCode
}

// ErrInvalidSignature occurs when the signature for a block of data is invalid.
type ErrInvalidSignature struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrInvalidSignature) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrInvalidSignature) Error() string {
	return fmt.Sprintf("the signature for the data is invalid: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrInvalidSignature) Code() int {
	return ErrInvalidSignatureCode
}

// ErrLoadCertificateFailure occurs when one or more certificates cannot be loaded.
type ErrLoadCertificateFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrLoadCertificateFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrLoadCertificateFailure) Error() string {
	return fmt.Sprintf("failed to load certificate(s): %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrLoadCertificateFailure) Code() int {
	return ErrLoadCertificateFailureCode
}

// ErrInvalidCertificate occurs when a certificate cannot be validated.
type ErrInvalidCertificate struct {
	CommonName         string
	ExpectedCommonName string
	Err                error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrInvalidCertificate) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrInvalidCertificate) Error() string {
	return fmt.Sprintf("failed to validate certificate(s): %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrInvalidCertificate) Code() int {
	return ErrInvalidCertificateCode
}

// ErrGeneratePrivateKeyFailure occurs when a private key for a certificate cannot be generated.
type ErrGeneratePrivateKeyFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrGeneratePrivateKeyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGeneratePrivateKeyFailure) Error() string {
	return fmt.Sprintf("failed to generate private key: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGeneratePrivateKeyFailure) Code() int {
	return ErrGeneratePrivateKeyFailureCode
}

// ErrGenerateCertificateFailure occurs when a certificate cannot be generated.
type ErrGenerateCertificateFailure struct {
	Err error
}

// InternalError the internal standard error object if there is one or nil if none is set.
func (e *ErrGenerateCertificateFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrGenerateCertificateFailure) Error() string {
	return fmt.Sprintf("failed to generate certificate: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrGenerateCertificateFailure) Code() int {
	return ErrGenerateCertificateFailureCode
}

// ErrEncodeFailure occurs when data cannot be encoded.
type ErrEncodeFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrEncodeFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrEncodeFailure) Error() string {
	return fmt.Sprintf("failed to encode data: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrEncodeFailure) Code() int {
	return ErrEncodeFailureCode
}

// ErrSignJWTTokenFailure occurs when a failure occurs while signing a token.
type ErrSignJWTTokenFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrSignJWTTokenFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrSignJWTTokenFailure) Error() string {
	return fmt.Sprintf("failed to sign JWT token: %s", e.Err)
}

// Code returns the corresponding error code.
func (e *ErrSignJWTTokenFailure) Code() int {
	return ErrSignJWTTokenFailureCode
}

// ErrInvalidTokenSignatureAlgorithm occurs when a token is signed with one algorithm but a different algorithm
// was expected.
type ErrInvalidTokenSignatureAlgorithm struct {
	Alg      interface{}
	Expected string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrInvalidTokenSignatureAlgorithm) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrInvalidTokenSignatureAlgorithm) Error() string {
	return fmt.Sprintf("JWT token was signed using a the '%v' algorithm but '%s' was expected", e.Alg, e.Expected)
}

// Code returns the corresponding error code.
func (e *ErrInvalidTokenSignatureAlgorithm) Code() int {
	return ErrInvalidJWTTokenSignatureAlgorithmCode
}

// ErrInvalidTokenClaims occurs when a token is signed with one algorithm but a different algorithm
// was expected.
type ErrInvalidTokenClaims struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrInvalidTokenClaims) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrInvalidTokenClaims) Error() string {
	return fmt.Sprintf("one or more JWT token claims are invalid: %s", e.Err)
}

// Code returns the corresponding error code.
func (e *ErrInvalidTokenClaims) Code() int {
	return ErrInvalidJWTTokenClaimsCode
}

// ErrParseJWTTokenFailure occurs when a token cannot be parsed or is invalid.
type ErrParseJWTTokenFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrParseJWTTokenFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrParseJWTTokenFailure) Error() string {
	return fmt.Sprintf("failed to parse the JWT token: %s", e.Err)
}

// Code returns the corresponding error code.
func (e *ErrParseJWTTokenFailure) Code() int {
	return ErrParseJWTTokenFailureCode
}
