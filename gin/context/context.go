package context

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	ut "github.com/go-playground/universal-translator"
	"github.com/golang-jwt/jwt/v4"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

var (
	// KeyRequestID is the name of the context key holding the unique request ID.
	KeyRequestID = "request_id"

	// KeyLogger is the name of the context key holding the request-specific logger.
	KeyLogger = "logger"

	// KeyJWT is the name of the context key holding the JWT token.
	KeyJWT = "jwt"

	// KeySessionData is the name of the key where session data is stored.
	KeySessionData = "session_data"

	// KeySessionID is the name of the key where the session ID is stored.
	KeySessionID = "session_id"

	// KeyTranslator is the name of the key where the i18n translator object is stored.
	KeyTranslator = "translator"
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
func GetJWT(c *gin.Context) *jwt.Token {
	if v, ok := c.Get(KeyJWT); ok {
		if jwt, ok := v.(*jwt.Token); ok {
			return jwt
		}
	}
	return nil
}

// GetSessionID returns the session ID stored in the context.
func GetSessionID(c *gin.Context) string {
	if v, ok := c.Get(KeySessionID); ok {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// MarshalSessionData saves the given data to the context.
func MarshalSessionData(c *gin.Context, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.Set(KeySessionData, string(b))
	return nil
}

// UnmarshalSessionData retrieves session data from the context.
//
// If session data was found and successfully unmarshaled into the given object, a true result is returned with
// a nil error. If no session data was found, a false result with a nil error is returned. If an error occurs
// while unmarshaling the data, a false result with an error is returned.
func UnmarshalSessionData(c *gin.Context, obj interface{}) (bool, error) {
	if v, ok := c.Get(KeySessionData); ok {
		if data, ok := v.(string); ok {
			if err := json.Unmarshal([]byte(data), &obj); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// GetTranslator returns the translator stored in the context.
func GetTranslator(c *gin.Context) ut.Translator {
	if v, ok := c.Get(KeyTranslator); ok {
		if t, ok := v.(ut.Translator); ok {
			return t
		}
	}
	return nil
}
