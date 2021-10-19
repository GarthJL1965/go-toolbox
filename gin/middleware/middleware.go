package middleware

// middlewareOptions is an interface that all middleware options must abide by.
type middlewareOptions interface {
	// GetErrorCodeHeader returns the name of the X header to use for holding the middleware's error code.
	GetErrorCodeHeader() string

	// GetErrorMessageHeader returns the name of the X header to use for holding the middleware's error message.
	GetErrorMessageHeader() string

	// SetErrorCodeHeader returns whether or not to set the error code header when an error occurs.
	SetErrorCodeHeader() bool

	// SetErrorMessageHeader returns whether or not to set the error code message when an error occurs.
	SetErrorMessageHeader() bool
}
