package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.imperva.dev/toolbox/crypto"
	tbcontext "go.imperva.dev/toolbox/gin/context"
)

var (
	// JWTAuthHeader defines the name of the header holding the JWT authorization info.
	JWTAuthHeader = "Authorization"

	// JWTAuthTokenType defines the type of authorization token for the AuthHeader.
	JWTAuthTokenType = "Bearer"
)

// JWTAuthHandler is an app-specific function that is used to verify authentication or authorization.
type JWTAuthHandler func(*gin.Context, *jwt.Token) (bool, error)

// JWTAuthOptions holds the options for configuring the JWTAuth middleware.
type JWTAuthOptions struct {
	// AuthnHandler is called to determine whether or not the user has successfully authenticated based on claims
	// in the token.
	AuthnHandler JWTAuthHandler

	// AuthznHandler is called to determine whether or not the user is authorized for the request based on
	// claims in the token.
	AuthzHandler JWTAuthHandler

	// AuthService is the JWT authentication service to use for verifying the token.
	AuthService crypto.JWTAuthService

	// Cookie defines the cookie in which to store the JWT token.
	Cookie struct {
		// Name of the cookie.
		Name string

		// MaxAge stores how long until the cookie expires.
		MaxAge time.Duration

		// Path restricts the cookie to a specific URI.
		Path string

		// Domain restricts the cookie to a specific domain.
		Domain string

		// Secure only allows the cookie to be transmitted over HTTPS connections.
		Secure bool

		// HttpOnly restricts the cookie from being accessed by anything such as JavaScript.
		HttpOnly bool
	}

	// EnableErrorCodeHeader indicates whether or not to set the custom X-*-Error-Code header if an error occurs.
	EnableErrorCodeHeader bool

	// EnableErrorMessageHeader indicates whether or not to set the custom X-*-Error-Message header if an error
	// occurs.
	EnableErrorMessageHeader bool

	// ErrorHandler is called if an error occurs while executing the middleware.
	ErrorHandler ErrorHandler

	// SaveToCookie indicates whether or not to save the JWT token to a cookie.
	SaveToCookie bool
}

// GetErrorCodeHeader returns the name of the X header to use for holding the middleware's error code.
func (o JWTAuthOptions) GetErrorCodeHeader() string {
	return "X-JWT-Auth-Error-Code"
}

// GetErrorMessageHeader returns the name of the X header to use for holding the middleware's error message.
func (o JWTAuthOptions) GetErrorMessageHeader() string {
	return "X-JWT-Auth-Error-Message"
}

// SetErrorCodeHeader returns whether or not to set the error code header when an error occurs.
func (o JWTAuthOptions) SetErrorCodeHeader() bool {
	return o.EnableErrorCodeHeader
}

// SetErrorMessageHeader returns whether or not to set the error code message when an error occurs.
func (o JWTAuthOptions) SetErrorMessageHeader() bool {
	return o.EnableErrorMessageHeader
}

// JWTAuth is a middleware function for authenticating and authorizing a caller via a JWT.
//
// Use the JWTAuth... global variables to change the default headers and/or token type used by this middleware.
//
// If no authentication or authorization handler is specified, the caller is assumed to be authenticated or
// authorized, respectively, as long as the token is valid.
//
// If an error occurs, the JWTAuthErrorCodeHeader will be set and, if additional error details are available,
// the JWTAuthErrorMessageHeader will contain the error message. The following error "codes" are used by this
// middleware for both the header and when calling the ErrorHandler, if one is supplied:
//
//  ◽ Token is missing from the request: jwt-missing-auth-token
//  ◽ Calling application failed to define a handler for creating the auth service: jwt-no-auth-service-defined
//  ◽ Token verification fails: jwt-verify-token-failed
//  ◽ Error returned by authentication handler: jwt-authentication-failed
//  ◽ Caller is not authenticated: jwt-not-authenticated
//  ◽ Error returned by authorization handler: jwt-authorization-failed
//  ◽ Caller is not authorized: jwt-not-authorized
//
// If an ErrorHandler is not supplied, the request will be aborted with the following HTTP status codes:
//
//  ◽ Token is missing from the request: 401
//  ◽ Calling application failed to define a handler for creating the auth service: 401
//  ◽ Token verification fails: 401
//  ◽ Error returned by authentication handler: 401
//  ◽ Caller is not authenticated: 401
//  ◽ Error returned by authorization handler: 403
//  ◽ Caller is not authorized: 403
//
// If an error handler is supplied, it is responsible for aborting the request or returning an appropriate
// response to the caller.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func JWTAuth(options JWTAuthOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := tbcontext.GetLogger(c)
		ctx := logger.WithContext(context.TODO())

		// validate the token and make sure the caller is authenticated and authorized
		authHeader := c.GetHeader(JWTAuthHeader)
		length := len(JWTAuthTokenType) + 1
		if len(authHeader) <= length {
			errorCode := "jwt-missing-auth-token"
			err := errors.New("authentication token is missing from request")
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msg(err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusUnauthorized)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		tokenString := authHeader[length:]
		if options.AuthService == nil {
			errorCode := "jwt-no-auth-service-defined"
			err := errors.New("no auth service for token verification was defined")
			setErrorHeaders(c, options, errorCode, err)
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusUnauthorized)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		token, err := options.AuthService.VerifyToken(tokenString, ctx)
		if err != nil {
			errorCode := "jwt-verify-token-failed"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("failed to verify JWT token: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusUnauthorized)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		if options.AuthnHandler != nil {
			authenticated, err := options.AuthnHandler(c, token)
			if err != nil {
				errorCode := "jwt-authentication-failed"
				setErrorHeaders(c, options, errorCode, err)
				logger.Error().Err(err).Msgf("failed to authenticate JWT token: %s", err.Error())
				if options.ErrorHandler == nil {
					c.AbortWithStatus(http.StatusUnauthorized)
				} else if options.ErrorHandler(c, errorCode, err) {
					c.Next()
				}
				return
			}
			if !authenticated {
				errorCode := "jwt-not-authenticated"
				setErrorHeaders(c, options, errorCode, errors.New("JWT token is not authenticated"))
				logger.Warn().Msg("JWT token is not authenticated")
				if options.ErrorHandler == nil {
					c.AbortWithStatus(http.StatusUnauthorized)
				} else if options.ErrorHandler(c, errorCode, nil) {
					c.Next()
				}
				return
			}
		}
		if options.AuthzHandler != nil {
			authorized, err := options.AuthnHandler(c, token)
			if err != nil {
				errorCode := "jwt-authorized-failed"
				setErrorHeaders(c, options, errorCode, err)
				logger.Error().Err(err).Msgf("failed to authorize JWT token: %s", err.Error())
				if options.ErrorHandler == nil {
					c.AbortWithStatus(http.StatusForbidden)
				} else if options.ErrorHandler(c, errorCode, err) {
					c.Next()
				}
				return
			}
			if !authorized {
				errorCode := "jwt-not-authorized"
				setErrorHeaders(c, options, errorCode,
					errors.New("JWT token is not authorized to perform the request"))
				logger.Warn().Msg("JWT token is not authorized to perform the request")
				if options.ErrorHandler == nil {
					c.AbortWithStatus(http.StatusForbidden)
				} else if options.ErrorHandler(c, errorCode, nil) {
					c.Next()
				}
				return
			}
		}

		// store the token and claims
		c.Set(tbcontext.KeyJWT, token)
		if options.SaveToCookie {
			c.SetCookie(options.Cookie.Name, tokenString, int(options.Cookie.MaxAge.Seconds()), options.Cookie.Path,
				options.Cookie.Domain, options.Cookie.Secure, options.Cookie.HttpOnly)
		}

		c.Next()
	}
}
