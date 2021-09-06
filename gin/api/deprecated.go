package api

import (
	"time"
)

// DeprecatedV1 holds deprecation information about a particular API call.
type DeprecatedV1 struct {
	// AsOf indicates the date and time when the API call was marked as deprecated.
	AsOf time.Time `json:"as_of"`

	// Message is a user-friendly warning message which can be displayed in a UI.
	Message string `json:"message"`

	// Details holds additional information about the deprecated call that may or may not be friendly for a UI.
	//
	// This field may not always be present in responses.
	Details string `json:"details,omitempty"`
}
