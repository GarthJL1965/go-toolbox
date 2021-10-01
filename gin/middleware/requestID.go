package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.impervaunity.io/pkg/toolbox/gin/context"
)

var (
	// RequestIDHeader represents the name of the header in which to store the request ID.
	RequestIDHeader = "X-Request-ID"
)

// RequestID is a middleware function for adding a unique request ID to every request.
//
// Use the RequestIDHeader global variable to change the default header used to store the
// request ID for the client.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.NewRandom()
		if err != nil {
			c.Set(context.KeyRequestID, "????????-????-????-????-????????????")
		} else {
			c.Set(context.KeyRequestID, id.String())
		}
		c.Set(RequestIDHeader, id)
		c.Next()
	}
}
