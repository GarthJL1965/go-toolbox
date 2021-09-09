package http

import (
	"fmt"
	"strings"
)

// Object error codes (2251-2500)
const (
	ErrParseUrlFailureCode      = 2251
	ErrProxyFailureCode         = 2252
	ErrCreateRequestFailureCode = 2253
	ErrDoRequestFailureCode     = 2254
	ErrReadResponseFailureCode  = 2255
)

// ErrParseUrlFailure occurs when there is an error parsing a URL.
type ErrParseUrlFailure struct {
	URL string
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrParseUrlFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrParseUrlFailure) Error() string {
	return fmt.Sprintf("failed to parse URL '%s': %s", e.URL, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrParseUrlFailure) Code() int {
	return ErrParseUrlFailureCode
}

// ErrorProxyFailure occurs when there is an error retrieving a proxy URL.
type ErrProxyFailure struct {
	URL string
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrProxyFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrProxyFailure) Error() string {
	return fmt.Sprintf("failed to check proxy status for URL '%s': %s", e.URL, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrProxyFailure) Code() int {
	return ErrProxyFailureCode
}

// ErrCreateRequestFailure occurs when there is an error creating a new HTTP request.
type ErrCreateRequestFailure struct {
	Method string
	URL    string
	Err    error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrCreateRequestFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrCreateRequestFailure) Error() string {
	return fmt.Sprintf("failed to create '%s' request for URL '%s': %s",
		strings.ToUpper(e.Method), e.URL, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrCreateRequestFailure) Code() int {
	return ErrCreateRequestFailureCode
}

// ErrDoRequestFailure occurs when there is an error executing a request.
type ErrDoRequestFailure struct {
	Method string
	URL    string
	Err    error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrDoRequestFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrDoRequestFailure) Error() string {
	return fmt.Sprintf("failed to perform %s request to '%s': %s", e.Method, e.URL, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrDoRequestFailure) Code() int {
	return ErrDoRequestFailureCode
}

// ErrReadResponseFailure occurs when there is an error reading a response body.
type ErrReadResponseFailure struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrReadResponseFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrReadResponseFailure) Error() string {
	return fmt.Sprintf("failed to read response body: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrReadResponseFailure) Code() int {
	return ErrReadResponseFailureCode
}

// ErrStatusCodeNotOK occurs when an HTTP status code of 400 or greater is returned.
type ErrStatusCodeNotOK struct {
	StatusCode int
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrStatusCodeNotOK) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrStatusCodeNotOK) Error() string {
	return fmt.Sprintf("HTTP request returned error code %d", e.StatusCode)
}

// Code returns the corresponding error code.
func (e *ErrStatusCodeNotOK) Code() int {
	return ErrReadResponseFailureCode
}
