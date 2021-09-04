package crypto

// Object error codes (1251-1500)
const (
	ErrDecodeFailureCode         = 1251
	ErrGenerateCipherFailureCode = 1252
	ErrGenerateGCMFailureCode    = 1253
	ErrDecryptFailureCode        = 1254
)

/*
// ErrParseUrlFailure occurs when there is an error parsing a URL.
type ErrParseUrlFailure struct {
	URL string
	Err error
}

// Error returns the string version of the error.
func (e *ErrParseUrlFailure) Error() string {
	return fmt.Sprintf("failed to parse URL '%s': %s", e.URL, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrParseUrlFailure) Code() int {
	return ErrParseUrlFailureCode
}
*/
