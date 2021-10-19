package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	redisrate "github.com/go-redis/redis_rate/v9"
	tbcontext "go.imperva.dev/toolbox/gin/context"
)

var (
	// RateLimitRemainingHeader is the header in which to store remaining rate limit information.
	RedisRateLimitRemainingHeader = "X-Redis-Rate-Limiter-Remaining"

	// RateLimitRetryAfterHeader is the header in which to store retry information.
	RedisRateLimitRetryAfterHeader = "X-Redis-Rate-Limiter-Retry-After"
)

// RedisRateLimiterOptions holds the options for configuring the RedisRateLimiter middleware.
type RedisRateLimiterOptions struct {
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

	// KeyLookupHandler is called to determine the name of the key in which to store client request rate information.
	// This would typically be an API key or a client IP address or some combination thereof.
	//
	// This field must NOT be nil.
	KeyLookupHandler func(*gin.Context) string

	// Rate indicates the rate limit settings.
	//
	// This field must NOT be nil.
	Rate redisrate.Limit
}

// GetErrorCodeHeader returns the name of the X header to use for holding the middleware's error code.
func (o RedisRateLimiterOptions) GetErrorCodeHeader() string {
	return "X-Redis-Rate-Limiter-Error-Code"
}

// GetErrorMessageHeader returns the name of the X header to use for holding the middleware's error message.
func (o RedisRateLimiterOptions) GetErrorMessageHeader() string {
	return "X-Redis-Rate-Limiter-Error-Message"
}

// SetErrorCodeHeader returns whether or not to set the error code header when an error occurs.
func (o RedisRateLimiterOptions) SetErrorCodeHeader() bool {
	return o.EnableErrorCodeHeader
}

// SetErrorMessageHeader returns whether or not to set the error code message when an error occurs.
func (o RedisRateLimiterOptions) SetErrorMessageHeader() bool {
	return o.EnableErrorMessageHeader
}

// RedisRateLimiter uses a Redis backend to enforce request rate limits.
//
// Use the RateLimit... and RedisRateLimit global variables to change the default headers used by this middleware.
//
// If an error occurs, the RateLimitErrorCodeHeader will be set and, if additional error details are available,
// the RateLimitErrorMessageHeader will contain the error message. The following error "codes" are used by this
// middleware for both the header and when calling the ErrorHandler, if one is supplied:
//
//  ◽ Failure while invoking rate limiter Allow function: rate-limiter-failure
//  ◽ Rate limit reached: rate-limited
//
// If an ErrorHandler is not supplied, the request will be aborted with the following HTTP status codes:
//
//  ◽ Failure while invoking rate limiter Allow function: 500
//  ◽ Rate limit reached: 429
//
// If an error handler is supplied, it is responsible for aborting the request or returning an appropriate
// response to the caller.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func RedisRateLimiter(options RedisRateLimiterOptions) gin.HandlerFunc {
	limiter := redisrate.NewLimiter(options.Client)
	return func(c *gin.Context) {
		key := options.KeyLookupHandler(c)
		logger := tbcontext.GetLogger(c).With().Str("limiter_key", key).Logger()

		// determine whether or not to allow the connection
		result, err := limiter.Allow(context.Background(), key, options.Rate)
		if err != nil {
			errorCode := "rate-limiter-failure"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("rate limiter failure: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		c.Set(RedisRateLimitRemainingHeader, strconv.Itoa(result.Remaining))

		// caller is rate limited
		if result.Allowed == 0 {
			errorCode := "rate-limited"
			seconds := int(result.RetryAfter / time.Second)
			setErrorHeaders(c, options, errorCode,
				fmt.Errorf("rate limit has been reached; retry in %d second(s)", seconds))
			c.Set(RedisRateLimitRetryAfterHeader, strconv.Itoa(seconds))
			logger.Warn().Msg("rate limit has been reached")
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusTooManyRequests)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		c.Next()
	}
}
