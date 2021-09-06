package api

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.imperva.dev/toolbox/gin/context"
)

// Well-known mime types.
const (
	MimeTypeAny  = "*/*"
	MimeTypeJSON = "application/json"
)

// NegotiateRequestType negotiates the type of request object supplied based on the Content-Type header.
//
// A Content-Type header should always be supplied in the request to avoid an error.
//
// The following errors are returned by this function:
// ErrUnsupportedRequestType
func NegotiateRequestType(c *gin.Context, supportedTypes map[string]string) (string, error) {
	contentType := c.Request.Header.Get("Content-Type")
	logger := context.GetLogger(c).With().Str("content_type", contentType).Logger()

	for ct, at := range supportedTypes {
		if contentType == ct {
			logger.Debug().Str("negotiated_media_type", at).Msgf("negotiated media type: %s", at)
			return at, nil
		}
	}

	e := &ErrUnsupportedRequestType{ContentType: contentType, SupportedTypes: supportedTypes}
	logger.Error().Err(e).Msg(e.Error())
	return "", e
}

// NegotiateResponseType negotiates the type of response object to return based on the Accept header.
//
// An Accept header should always be supplied in the request to avoid an error.
//
// The following errors are returned by this function:
// ErrUnsupportedResponseType
func NegotiateResponseType(c *gin.Context, supportedTypes map[string]string) (string, error) {
	accept := c.Request.Header.Get("Accept")
	logger := context.GetLogger(c).With().Str("accept", accept).Logger()

	// parse the accepted mime types
	mimeTypes := []acceptedType{}
	for _, t := range strings.Split(accept, ",") {
		t = strings.TrimSpace(t)
		at, err := parseAcceptedType(t)
		if err != nil {
			logger.Warn().Str("mime_type", t).Msgf("skipping invalid mime type '%s': %s", t, err.Error())
		} else {
			logger.Debug().Str("mime_type", at.mimeType).Float32("quality", at.quality).
				Msgf("found accepted mime type: %s", at.mimeType)
			mimeTypes = append(mimeTypes, at)
		}
	}
	sort.Slice(mimeTypes, func(i, j int) bool {
		return mimeTypes[i].quality < mimeTypes[j].quality
	})

	// loop through the preferred mime types in order of 'quality'
	for _, t := range mimeTypes {
		if at, ok := supportedTypes[t.mimeType]; ok {
			logger.Debug().Str("response_type", at).Msgf("negotiated media type: %s", at)
			return at, nil
		}
	}

	e := &ErrUnsupportedResponseType{Accept: accept, SupportedTypes: supportedTypes}
	logger.Error().Err(e).Msg(e.Error())
	return "", e
}

// acceptedType holds details on a mime type specified in the Accept header.
type acceptedType struct {
	mimeType string
	quality  float32
}

// parseAcceptedType parses the raw mime type into an accepted type.
func parseAcceptedType(mimeTypes string) (acceptedType, error) {
	mimeTypes = strings.TrimSpace(mimeTypes)

	pattern := regexp.MustCompile(`^([\w*]+\/[-+.*\w]+)(;q=([0-9]+(\.[0-9]+)?))?$`)
	matches := pattern.FindStringSubmatch(mimeTypes)
	if len(matches) == 0 {
		return acceptedType{}, fmt.Errorf("%s: mime type is not valid", mimeTypes)
	}
	q := float32(1.0)
	if matches[3] != "" {
		v, err := strconv.ParseFloat(matches[3], 32)
		if err != nil {
			return acceptedType{}, err
		}
		q = float32(v)
	}
	return acceptedType{
		mimeType: matches[1],
		quality:  q,
	}, nil
}
