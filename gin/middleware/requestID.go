package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.imperva.dev/toolbox/gin/context"
)

// RequestID is a middleware function for adding a unique request ID to every request.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.NewRandom()
		if err != nil {
			c.Set(context.KeyRequestID, "????????-????-????-????-????????????")
		} else {
			c.Set(context.KeyRequestID, id.String())
		}
		c.Next()
	}
}
