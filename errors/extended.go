package errors

// ExtendedError represents an extension to the error interface by adding the ability to return an error code as well.
type ExtendedError interface {
	Error() string
	Code() int
}
