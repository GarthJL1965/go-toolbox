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

type JWTAuthService interface {
	GenerateToken(JWTClaims, context.Context) (string, error)
	ValidateToken(string, context.Context) (*JWTClaims, error)
}

type JWTClaims struct {
	jwt.StandardClaims
	AppClaims map[string]interface{}
}

func (j JWTClaims) Valid() error {
	return j.StandardClaims.Valid()
}

type JWTAuthHMACService struct {
	secret []byte
}

func NewJWTAuthHMACService(secret []byte) *JWTAuthHMACService {
	return &JWTAuthHMACService{secret: secret}
}

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

type JWTAuthRSAService struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewJWTAuthRSAService(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *JWTAuthRSAService {
	return &JWTAuthRSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

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

type JWTAuthECDSAService struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

func NewJWTAuthECDSAService(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *JWTAuthECDSAService {
	return &JWTAuthECDSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

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
