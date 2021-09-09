package api

import "fmt"

// Object error codes (3001-3250)
const (
	ErrUnsupportedRequestTypeCode  = 3001
	ErrUnsupportedResponseTypeCode = 3002
	ErrRequestResponseMismatchCode = 3003
)

// ErrUnsupportedRequestType occurs when the Content-Type header is not a supported media type.
type ErrUnsupportedRequestType struct {
	ContentType    string
	SupportedTypes map[string]string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrUnsupportedRequestType) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrUnsupportedRequestType) Error() string {
	if e.ContentType != "" {
		return fmt.Sprintf("unsupported media type in the request: %s", e.ContentType)
	}
	return "no media type was supplied in the request"
}

// Code returns the corresponding error code.
func (e *ErrUnsupportedRequestType) Code() int {
	return ErrUnsupportedRequestTypeCode
}

// ErrUnsupportedResponseType occurs when the Accept header contains no supported media types.
type ErrUnsupportedResponseType struct {
	Accept         string
	SupportedTypes map[string]string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrUnsupportedResponseType) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrUnsupportedResponseType) Error() string {
	if e.Accept != "" {
		return fmt.Sprintf("none of the supported media types are acceptable as a response: %s", e.Accept)
	}
	return "no accepted media types were supplied in the request"
}

// Code returns the corresponding error code.
func (e *ErrUnsupportedResponseType) Code() int {
	return ErrUnsupportedResponseTypeCode
}

// ErrRequestResponseMismatch occurs when the negotiated request and response media types are not identical.
type ErrRequestResponseMismatch struct {
	RequestType  string
	ResponseType string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrRequestResponseMismatch) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrRequestResponseMismatch) Error() string {
	return fmt.Sprintf("request and response types do not match: %s != %s", e.RequestType, e.ResponseType)
}

// Code returns the corresponding error code.
func (e *ErrRequestResponseMismatch) Code() int {
	return ErrRequestResponseMismatchCode
}
