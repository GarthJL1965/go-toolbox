package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// Object error codes (3501-3750)
const (
	ErrLoadIPLocationDBCode = 3501
)

// ErrorHandler is called when an error occurs within certain middlewares.
//
// The current gin context is passed along with a custom error string "code" (as noted in the middleware's
// documentation) indicating the error that occurred along with any specific error information. If no additional
// error information is available, the caller should set the error parameter to nil. No handler function should
// assume the error is non-nil.
//
// The handler should return true if the middleware should continue running or false if it should return
// immediately.
type ErrorHandler func(*gin.Context, string, error) bool

// ErrLoadIPLocationDB occurs when there is an error loading the IP location database.
type ErrLoadIPLocationDB struct {
	Path string
	Err  error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrLoadIPLocationDB) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrLoadIPLocationDB) Error() string {
	return fmt.Sprintf("failed to load database file '%s': %s", e.Path, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrLoadIPLocationDB) Code() int {
	return ErrLoadIPLocationDBCode
}

// setErrorHeaders is used to set error headers for the context when middleware fails.
func setErrorHeaders(c *gin.Context, m middlewareOptions, code string, err error) {
	if m.SetErrorCodeHeader() {
		c.Header(m.GetErrorCodeHeader(), code)
	}
	if m.SetErrorMessageHeader() {
		c.Header(m.GetErrorCodeHeader(), err.Error())
	}
}
