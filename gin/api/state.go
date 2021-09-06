package api

// State data field names.
const (
	StateFieldCode           = "code"
	StateFieldDeprecated     = "deprecated"
	StateFieldMimeType       = "mime_type"
	StateFieldMessage        = "message"
	StateFieldPrivateMessage = "private_message"
	StateFieldRequestID      = "request_id"
	StateFieldResult         = "result"
)

// Valid values for the "result" field in an API response's state.
const (
	ResultSuccess = "success"
	ResultError   = "error"
	ResultWarning = "warn"
)

// StateV1 holds response state information returned by the
type StateV1 struct {
	// Code refers to a status code indicating the return result from the API call.
	Code int `json:"code"`

	// Deprecation information
	//
	// This field may not always be present in responses.
	Deprecated *DeprecatedV1 `json:"deprecated,omitempty"`

	// MimeType indicates the type of object being returned by the API call.
	MimeType string `json:"mime_type"`

	// Message will be any message associated with the API call.
	//
	// This message is safe to display to an end user in a UI.
	Message string `json:"message"`

	// PrivateMessage will be any internal messages associated with the API call.
	//
	// This message is considered internal and should not be displayed in a UI but may be logged for informational
	// purposes.
	//
	//This field may not always be present in responses.
	PrivateMessage string `json:"private_message,omitempty"`

	// RequestID holds a unique request ID associated with the API call, so it can be used in tracing messages.
	RequestID string `json:"request_id"`

	// Result will be a pre-defined status from the list: success, error or warn
	Result string `json:"result"`
}

// StateV1FromData extracts and returns a StateV1 object from the arbitrary data passed to the function.
func StateV1FromData(data map[string]interface{}) StateV1 {
	s := StateV1{}
	if v, ok := data[StateFieldCode]; ok {
		s.Code, _ = v.(int)
	}
	if v, ok := data[StateFieldDeprecated]; ok {
		s.Deprecated, _ = v.(*DeprecatedV1)
	}
	if v, ok := data[StateFieldMimeType]; ok {
		s.MimeType, _ = v.(string)
	}
	if v, ok := data[StateFieldMessage]; ok {
		s.Message, _ = v.(string)
	}
	if v, ok := data[StateFieldPrivateMessage]; ok {
		s.PrivateMessage, _ = v.(string)
	}
	if v, ok := data[StateFieldRequestID]; ok {
		s.RequestID, _ = v.(string)
	}
	if v, ok := data[StateFieldResult]; ok {
		s.Result, _ = v.(string)
	}
	return s
}
