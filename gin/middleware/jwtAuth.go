package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.imperva.dev/toolbox/crypto"
	tbcontext "go.imperva.dev/toolbox/gin/context"
)

// JWTAuthHandler is an app-specific function that is used to verify authentication or authorization.
type JWTAuthHandler func(*gin.Context, *crypto.JWTClaims, context.Context) bool

type JWTOptions struct {
	AuthHeader   string
	AuthnHandler JWTAuthHandler
	AuthzHandler JWTAuthHandler
	AuthService  crypto.JWTAuthService
	Cookie       struct {
		Name     string
		MaxAge   time.Duration
		Path     string
		Domain   string
		Secure   bool
		HttpOnly bool
	}
	SaveToCookie bool
	TokenType    string
}

// JWTAuth is a middleware function for authenticating and authorizing a caller via a JWT.
//
// If the JWT is invalid or the caller is not authenticated, the request is aborted with a 401 error code.
// If the caller is not authorized to access the resource, the request is aborted with a 403 error code.
//
// If no authentication or authorization handler is specified, the caller is assumed to be authenticated or
// authorized, respectively, as long as the token is valid.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func JWTAuth(options JWTOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := tbcontext.GetLogger(c)
		ctx := logger.WithContext(context.TODO())

		// validate the token and make sure the caller is authenticated and authorized
		headerName := "Authorization"
		if options.AuthHeader != "" {
			headerName = options.AuthHeader
		}
		authHeader := c.GetHeader(headerName)
		tokenType := "Bearer"
		if options.TokenType != "" {
			tokenType = options.TokenType
		}
		length := len(tokenType) + 1
		if len(authHeader) <= length {
			c.AbortWithStatus(http.StatusUnauthorized)
			// logger
			return
		}
		tokenString := authHeader[length:]
		claims, err := options.AuthService.ValidateToken(tokenString, ctx)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			// logger
			return
		}
		if options.AuthnHandler != nil && !options.AuthnHandler(c, claims, ctx) {
			c.AbortWithStatus(http.StatusUnauthorized)
			// logger
			return
		}
		if options.AuthzHandler != nil && !options.AuthzHandler(c, claims, ctx) {
			c.AbortWithStatus(http.StatusForbidden)
			// logger
			return
		}

		// store the token and claims
		c.Set(tbcontext.KeyJWT, tokenString)
		c.Set(tbcontext.KeyJWTClaims, claims)
		if options.SaveToCookie {
			c.SetCookie(options.Cookie.Name, tokenString, int(options.Cookie.MaxAge.Seconds()), options.Cookie.Path,
				options.Cookie.Domain, options.Cookie.Secure, options.Cookie.HttpOnly)
		}

		c.Next()
	}
}
