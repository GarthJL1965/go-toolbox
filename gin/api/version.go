package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.impervaunity.io/pkg/toolbox/gin/context"
)

// VersionedResponseObject is an interface describing an object that can be used to render a response.
type VersionedResponseObject interface {
	Render(map[string]interface{})
}

// VersionedHandler is used to store a list of mime types which map to a particular handler.
type VersionedHandler struct {
	MimeTypeAliases []string
	Handler         gin.HandlerFunc
}

// VersionedHandlerMap is used to map a specific mime type to a particular handler.
//
// Additional aliases for the mime type should be specified using the VersionHandler object. For example,
// if the same handler should be used for application/json requests, add the application/json alias to the
// VersionedHandler object.
type VersionedHandlerMap map[string]VersionedHandler

// NegotiateVersion negotiates the versioned request/response objects based on headers.
//
// Content-Type and Accept headers should be supplied in every API request.
//
// The following errors are returned by this function:
// ErrRequestResposneMismatch, any error from the NegotiateRequestType() or NegotiateResponseType() functions
func NegotiateVersion(c *gin.Context, handlers VersionedHandlerMap) (gin.HandlerFunc, error) {
	logger := context.GetLogger(c)

	// create a map of all mime type aliases to the actual mime type
	supportedTypes := map[string]string{}
	for mimeType, v := range handlers {
		supportedTypes[mimeType] = mimeType
		for _, a := range v.MimeTypeAliases {
			supportedTypes[a] = mimeType
		}
	}

	// negotiate the actual request / response types based on mime type or mime type alias
	reqType, err := NegotiateRequestType(c, supportedTypes)
	if err != nil {
		return nil, err
	}
	respType, err := NegotiateResponseType(c, supportedTypes)
	if err != nil {
		return nil, err
	}
	if reqType != respType {
		e := &ErrRequestResponseMismatch{RequestType: reqType, ResponseType: respType}
		logger.Error().Err(e).Msg(e.Error())
		return nil, e
	}
	return handlers[respType].Handler, nil
}

// UnversionedJSONObject returns a mime type for an unversioned application-specific JSON object.
func UnversionedJSONObject(vendor, app, object string) string {
	return fmt.Sprintf("application/vnd.%s.%s.%s+json", vendor, app, object)
}

// UnversionedObject returns a mime type for an unversioned application-specific object.
func UnversionedObject(vendor, app, object, format string) string {
	return fmt.Sprintf("application/vnd.%s.%s.%s+%s", vendor, app, object, format)
}

// VersionedJSONObject returns a mime type for an versioned application-specific JSON object.
func VersionedJSONObject(vendor, app, object string, version uint) string {
	return fmt.Sprintf("application/vnd.%s.%s.%s.v%d+json", vendor, app, object, version)
}

// VersionedObject returns a mime type for an versioned application-specfic object.
func VersionedObject(vendor, app, object, format string, version uint) string {
	return fmt.Sprintf("application/vnd.%s.%s.%s.v%d+%s", vendor, app, object, version, format)
}
