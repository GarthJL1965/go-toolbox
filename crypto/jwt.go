package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v4"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// JWTAuthService represents any object that is able to generate new JWT tokens and also validate them.
type JWTAuthService interface {
	// GenerateToken should generate a new JWT token with the given claims and return the encoded JWT token.
	GenerateToken(jwt.Claims, context.Context) (string, error)

	// VerifyToken should parse and verify the token string and return the resulting JWT token for further validation.
	VerifyToken(string, context.Context) (*jwt.Token, error)
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
//
// The following errors are returned by this function:
// ErrSignJWTTokenFailure
func (j *JWTAuthHMACService) GenerateToken(claims jwt.Claims, ctx context.Context) (string, error) {
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

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The following errors are returned by this function:
// ErrInvalidTokenSignatureAlgorithm, ErrParseJWTTokenFailure
func (j *JWTAuthHMACService) VerifyToken(encodedToken string, ctx context.Context) (*jwt.Token, error) {
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
		e := &ErrParseJWTTokenFailure{
			Err: err,
		}
		logger.Error().Err(e).Msg(e.Error())
		return nil, e
	}
	return token, nil
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
//
// The following errors are returned by this function:
// ErrSignJWTTokenFailure
func (j *JWTAuthRSAService) GenerateToken(claims jwt.Claims, ctx context.Context) (string, error) {
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

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The following errors are returned by this function:
// ErrInvalidTokenSignatureAlgorithm, ErrParseJWTTokenFailure
func (j *JWTAuthRSAService) VerifyToken(encodedToken string, ctx context.Context) (*jwt.Token, error) {
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
		e := &ErrParseJWTTokenFailure{
			Err: err,
		}
		logger.Error().Err(e).Msg(e.Error())
		return nil, e
	}
	return token, nil
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
//
// The following errors are returned by this function:
// ErrSignJWTTokenFailure
func (j *JWTAuthECDSAService) GenerateToken(claims jwt.Claims, ctx context.Context) (string, error) {
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

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The following errors are returned by this function:
// ErrInvalidTokenSignatureAlgorithm, ErrParseJWTTokenFailure
func (j *JWTAuthECDSAService) VerifyToken(encodedToken string, ctx context.Context) (*jwt.Token, error) {
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
		e := &ErrParseJWTTokenFailure{
			Err: err,
		}
		logger.Error().Err(e).Msg(e.Error())
		return nil, e
	}
	return token, nil
}
