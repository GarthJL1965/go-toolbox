package errors

// ExtendedError represents an extension to the error interface by adding the ability to return an error code as well.
type ExtendedError interface {
	// InternalError returns the internal standard error object if there is one or nil if none is set.
	InternalError() error

	// Error returns the string version of the error.
	Error() string

	// Code returns the corresponding error code.
	Code() int
}
