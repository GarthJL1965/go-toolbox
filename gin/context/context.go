package context

import (
	"github.com/gin-gonic/gin"
	"go.imperva.dev/toolbox/crypto"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

const (
	// KeyRequestID is the name of the context key holding the unique request ID.
	KeyRequestID = "request_id"

	// KeyLogger is the name of the context key holding the request-specific logger.
	KeyLogger = "logger"

	// KeyJWT is the name of the context key holding the JWT string.
	KeyJWT = "jwt"

	// KeyJWTClaims is the name of the context key holding the JWT claim data.
	KeyJWTClaims = "jwt_claims"
)

// GetRequestID returns the request ID from the context.
func GetRequestID(c *gin.Context) string {
	if v, ok := c.Get(KeyRequestID); ok {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return "????????-????-????-????-????????????"
}

// GetLogger returns the request ID from the context.
func GetLogger(c *gin.Context) zerolog.Logger {
	if v, ok := c.Get(KeyLogger); ok {
		if l, ok := v.(zerolog.Logger); ok {
			return l
		}
	}
	return log.Logger
}

// GetJWT returns the JWT from the context.
func GetJWT(c *gin.Context) string {
	if v, ok := c.Get(KeyJWT); ok {
		if t, ok := v.(string); ok {
			return t
		}
	}
	return ""
}

// GetJWTClaims returns the JWT claims from the context.
func GetJWTClaims(c *gin.Context) *crypto.JWTClaims {
	if v, ok := c.Get(KeyJWTClaims); ok {
		if c, ok := v.(*crypto.JWTClaims); ok {
			return c
		}
	}
	return nil
}
