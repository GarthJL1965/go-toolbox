package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v4"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// JWTAuthService represents any object that is able to generate new JWT tokens and also validate them.
type JWTAuthService interface {
	// GenerateToken should generate a new JWT token with the given claims and return the encoded JWT token.
	GenerateToken(JWTClaims, context.Context) (string, error)

	// ValidateToken should parse the token string and ensure it is valid, returning the claims associated with it.
	ValidateToken(string, context.Context) (*JWTClaims, error)
}

// JWTClaims holds standard JWT claims in addition to any application-specific claims.
type JWTClaims struct {
	jwt.StandardClaims
	AppClaims map[string]interface{}
}

// Valid returns whether or not the standard claims are valid.
func (j JWTClaims) Valid() error {
	return j.StandardClaims.Valid()
}

// JWTAuthHMACService creates and validates JWT tokens that are signed with an HMAC256-hashed secret.
//
// You must use the same validate the JWT token as was used to generate it. Otherwise, validation will fail.
type JWTAuthHMACService struct {
	secret []byte
}

// NewJWTAuthHMACService creates an initializes a new service object.
func NewJWTAuthHMACService(secret []byte) *JWTAuthHMACService {
	return &JWTAuthHMACService{secret: secret}
}

// GenerateToken generates a new JWT token with the given claims.
func (j *JWTAuthHMACService) GenerateToken(claims JWTClaims, ctx context.Context) (string, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		e := &ErrSignJWTTokenFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	return signedToken, nil
}

// ValidateToken validates the given token and returns the claims associated with it.
func (j *JWTAuthHMACService) ValidateToken(encodedToken string, ctx context.Context) (*JWTClaims, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			e := &ErrInvalidTokenSignatureAlgorithm{Alg: token.Header["alg"], Expected: "HS256"}
			logger.Error().Err(e).Msg(e.Error())
			return nil, e
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, err
	}

	// extract the claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		e := &ErrInvalidTokenClaims{Err: errors.New("claims are not in the expected format")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return claims, nil
}

// JWTAuthRSAService creates and validates JWT tokens that are signed with a private RSA key and validated with a
// public RSA key.
//
// You must use the same key pair to validate the JWT token as was used to generate it. Otherwise, validation
// will fail.
type JWTAuthRSAService struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewJWTAuthRSAService creates an initializes a new service object.
func NewJWTAuthRSAService(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *JWTAuthRSAService {
	return &JWTAuthRSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// GenerateToken generates a new JWT token with the given claims.
func (j *JWTAuthRSAService) GenerateToken(claims JWTClaims, ctx context.Context) (string, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		e := &ErrSignJWTTokenFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	return signedToken, nil
}

// ValidateToken validates the given token and returns the claims associated with it.
func (j *JWTAuthRSAService) ValidateToken(encodedToken string, ctx context.Context) (*JWTClaims, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			e := &ErrInvalidTokenSignatureAlgorithm{Alg: token.Header["alg"], Expected: "RS256"}
			logger.Error().Err(e).Msg(e.Error())
			return nil, e
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	// extract the claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		e := &ErrInvalidTokenClaims{Err: errors.New("claims are not in the expected format")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return claims, nil
}

// JWTAuthECDSAService creates and validates JWT tokens that are signed with a private ECDSA key and validated with a
// public ECDSA key.
//
// You must use the same key pair to validate the JWT token as was used to generate it. Otherwise, validation
// will fail.
type JWTAuthECDSAService struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

// NewJWTAuthECDSAService creates an initializes a new service object.
func NewJWTAuthECDSAService(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *JWTAuthECDSAService {
	return &JWTAuthECDSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// GenerateToken generates a new JWT token with the given claims.
func (j *JWTAuthECDSAService) GenerateToken(claims JWTClaims, ctx context.Context) (string, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		e := &ErrSignJWTTokenFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return "", e
	}
	return signedToken, nil
}

// ValidateToken validates the given token and returns the claims associated with it.
func (j *JWTAuthECDSAService) ValidateToken(encodedToken string, ctx context.Context) (*JWTClaims, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			e := &ErrInvalidTokenSignatureAlgorithm{Alg: token.Header["alg"], Expected: "RS256"}
			logger.Error().Err(e).Msg(e.Error())
			return nil, e
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	// extract the claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		e := &ErrInvalidTokenClaims{Err: errors.New("claims are not in the expected format")}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return claims, nil
}
