package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
	"go.impervaunity.io/pkg/toolbox/gin/context"
)

// Logger is a middleware function for logging requests to the server.
//
// Be sure to include the RequestID middleware before including this middleware so that a unique request ID is
// written to log messages associated with the current gin context.
func Logger(excludeRequests ExcludeHTTPRequests) gin.HandlerFunc {
	return func(c *gin.Context) {
		// do not bother logging anything if the method/path are ignored
		if excludeRequestFromLog(c.Request, excludeRequests) {
			logger := zerolog.New(ioutil.Discard)
			c.Set(context.KeyLogger, logger)
			c.Next()
			return
		}

		// save the start time and request ID
		start := time.Now().UTC()
		logger := log.With().
			Str("request_id", context.GetRequestID(c)).
			Logger()
		c.Set(context.KeyLogger, logger)
		c.Next()

		// request has completed so write the details to the log
		end := time.Now().UTC()
		status := c.Writer.Status()
		level := zerolog.InfoLevel
		if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
			level = zerolog.WarnLevel
		} else if status >= http.StatusInternalServerError {
			level = zerolog.ErrorLevel
		}
		logger.WithLevel(level).
			Int("status", status).
			Str("method", c.Request.Method).
			Dur("latency", end.Sub(start)).
			Str("user_agent", c.Request.UserAgent()).
			Str("path", c.Request.URL.Path).
			Str("client_ip", c.ClientIP()).
			Str("x_forwarded_for", c.Request.Header.Get("X-Forwarded-For")).
			Str("query", c.Request.URL.RawQuery).
			Str("request_id", context.GetRequestID(c)).
			Msgf("%d %s %s", status, c.Request.Method, c.Request.URL.Path)
	}
}

// ExcludeHTTPRequest simply holds the method and path information for any type of HTTP request to
// exclude from logging.
type ExcludeHTTPRequest struct {
	// HTTP method to ignore or "*" to ignore all methods.
	Method string

	// Path is a regular expression to use in order to match the request path.
	Path string
}

// String returns the string representation of the object.
func (r *ExcludeHTTPRequest) String() string {
	return fmt.Sprintf("%s %s", strings.ToUpper(r.Method), r.Path)
}

// Set parses the given string value into the object.
func (r *ExcludeHTTPRequest) Set(str string) error {
	result := strings.SplitN(str, " ", 2)
	method := strings.TrimSpace(strings.ToUpper(result[0]))
	path := strings.TrimSpace(result[1])

	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		r.Method = method
	default:
		return fmt.Errorf("%s: not a valid HTTP request method", method)
	}

	_, err := regexp.Compile(path)
	if err != nil {
		return err
	}
	r.Path = path
	return nil
}

// Type returns the type of the object.
func (r *ExcludeHTTPRequest) Type() string {
	return "ExcludeHTTPRequest"
}

// ExcludeHTTPRequests represents and array of ExcludeHTTPRequest objects.
type ExcludeHTTPRequests []ExcludeHTTPRequest

// String returns the string representation of the object.
func (r ExcludeHTTPRequests) String() string {
	requests := []string{}
	for _, req := range r {
		requests = append(requests, req.String())
	}
	return strings.Join(requests, ",")
}

// Set parses the given string value into the object.
func (r ExcludeHTTPRequests) Set(str string) error {
	requests := strings.Split(str, ",")
	newRequests := []ExcludeHTTPRequest{}
	for _, req := range requests {
		request := ExcludeHTTPRequest{}
		if err := request.Set(req); err != nil {
			return err
		}
		newRequests = append(newRequests, request)
	}
	r = newRequests
	return nil
}

// Type returns the type of the object.
func (r ExcludeHTTPRequests) Type() string {
	return "ExcludeHTTPRequests"
}

// excludeRequestFromLog determines whether or not the given request should be excluded from the log.
func excludeRequestFromLog(r *http.Request, excludeRequests ExcludeHTTPRequests) bool {
	if excludeRequests == nil {
		return false
	}

	path := r.URL.Path
	raw := r.URL.RawQuery
	if raw != "" {
		path = path + "?" + raw
	}

	for _, ignore := range excludeRequests {
		if ignore.Method != "*" && !strings.EqualFold(ignore.Method, r.Method) {
			continue
		}
		expr, err := regexp.Compile(ignore.Path)
		if err != nil {
			log.Error().Err(err).Msgf("ignoring invalid log request path expression '%s': %s",
				ignore.Path, err.Error())
			continue
		}
		if expr.MatchString(path) {
			return true
		}
	}
	return false
}
