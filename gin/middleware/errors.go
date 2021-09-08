package middleware

import (
	"github.com/gin-gonic/gin"
)

// Object error codes (3501-3750)
const ()

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
