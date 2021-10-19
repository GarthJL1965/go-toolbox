package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	tbcontext "go.imperva.dev/toolbox/gin/context"
)

// RedisSessionOptions holds the options for configuring the RedisSession middleware.
type RedisSessionOptions struct {
	// Client points to the Redis client object.
	//
	// This field must NOT be nil.
	Client *redis.Client

	// EnableErrorCodeHeader indicates whether or not to set the custom X-*-Error-Code header if an error occurs.
	EnableErrorCodeHeader bool

	// EnableErrorMessageHeader indicates whether or not to set the custom X-*-Error-Message header if an error
	// occurs.
	EnableErrorMessageHeader bool

	// ErrorHandler is called if an error occurs while executing the middleware.
	ErrorHandler ErrorHandler

	// SessionIDLookupHandler is called to retrieve the ID for the session.
	//
	// This function should return the session ID with a nil error on success or an empty string with an error on
	// failure.
	//
	// By using a handler function, the application can obtain the session ID in any number of ways such as by
	// inspecting a JWT claim or simply using a cookie.
	//
	// This field must NOT be nil.
	SessionIDLookupHandler func(*gin.Context) (string, error)

	// TTL indicates the length session data will be stored before it expires.
	TTL time.Duration
}

// GetErrorCodeHeader returns the name of the X header to use for holding the middleware's error code.
func (o RedisSessionOptions) GetErrorCodeHeader() string {
	return "X-Redis-Session-Error-Code"
}

// GetErrorMessageHeader returns the name of the X header to use for holding the middleware's error message.
func (o RedisSessionOptions) GetErrorMessageHeader() string {
	return "X-Redis-Session-Error-Message"
}

// SetErrorCodeHeader returns whether or not to set the error code header when an error occurs.
func (o RedisSessionOptions) SetErrorCodeHeader() bool {
	return o.EnableErrorCodeHeader
}

// SetErrorMessageHeader returns whether or not to set the error code message when an error occurs.
func (o RedisSessionOptions) SetErrorMessageHeader() bool {
	return o.EnableErrorMessageHeader
}

// RedisSession uses a Redis backend to store session information.
//
// Session data must always be serialized into a JSON string. Use the context.UnmarshalSessionData() and
// context.MarshalSessionData() to access and update session data in your application. If the data stored
// in the context is not a string, empty session data will be written back to Redis.
//
// Use the Session... global variables to change the default headers used by this middleware.
//
// If an error occurs, the SessionErrorCodeHeader will be set and, if additional error details are available, the
// SessionErrorMessageHeader will contain the error message. The following error "codes" are used by this
// middleware for both the header and when calling the ErrorHandler, if one is supplied:
//
//  ◽ Failure while retrieving session ID: get-session-id-failure
//  ◽ Failure while getting session data from Redis: get-session-data-failure
//  ◽ Failure while storing session data in Redis: store-session-data-failure
//
// If an ErrorHandler is not supplied, the request will be aborted with the following HTTP status codes:
//
//  ◽ Failure while retrieving session ID: 500
//  ◽ Failure while getting session data from Redis: 500
//  ◽ Failure while storing session data in Redis: 500
//
// If an error handler is supplied, it is responsible for aborting the request or returning an appropriate
// response to the caller.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func RedisSession(options RedisSessionOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := tbcontext.GetLogger(c)

		// get the session ID using the handler - session ID could come from a JWT or cookie or elsewhere
		id, err := options.SessionIDLookupHandler(c)
		if err != nil {
			errorCode := "get-session-id-failure"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("failed to retrieve session ID: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}

		// get session data from Redis
		result, err := options.Client.Get(context.Background(), id).Result()
		if err == redis.Nil {
			result = "{}"
		} else if err != redis.Nil {
			errorCode := "get-session-data-failure"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("failed to retrieve session data: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}

		// store session information in the context
		c.Set(tbcontext.KeySessionID, id)
		c.Set(tbcontext.KeySessionData, result)

		c.Next()

		// get session information from the context
		// it should be a marshaled JSON string; if it isn't, just save an empty session because it's been manipulated
		// incorrectly by something else
		data := "{}"
		if v, ok := c.Get(tbcontext.KeySessionData); ok {
			if s, ok := v.(string); ok {
				data = s
			}
		}

		// save updated session data back to Redis
		if err := options.Client.Set(context.Background(), id, data, options.TTL).Err(); err != nil {
			errorCode := "store-session-data-failure"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("failed to store session data: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else {
				options.ErrorHandler(c, errorCode, err)
			}
			return
		}
	}
}
