package k8s

import (
	"fmt"
)

// Object error codes (1751-2000)
const (
	ErrWaitConditionInvalidCode = 1751
	ErrResourceWaitFailureCode  = 1752
)

// ErrWaitConditionInvalid occurs when a wait condition is invalid.
type ErrWaitConditionInvalid struct {
	Err error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrWaitConditionInvalid) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrWaitConditionInvalid) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("the wait condition is not valid: %s", e.Err.Error())
	}
	return "the wait condition is not valid"
}

// Code returns the corresponding error code.
func (e *ErrWaitConditionInvalid) Code() int {
	return ErrWaitConditionInvalidCode
}

// ErrResourceWaitFailure occurs when an error occurs while waiting for a resource.
type ErrResourceWaitFailure struct {
	Kind      string
	Name      string
	Selectors string
	Err       error
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrResourceWaitFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrResourceWaitFailure) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("failed to wait for %s resource named '%s': %s",
			e.Kind, e.Name, e.Err.Error())
	}
	if e.Selectors != "" {
		return fmt.Sprintf("failed to wait for %s resource matching selectors '%s': %s",
			e.Kind, e.Selectors, e.Err.Error())
	}
	return fmt.Sprintf("failed to wait for %s resource: %s", e.Kind, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrResourceWaitFailure) Code() int {
	return ErrResourceWaitFailureCode
}
