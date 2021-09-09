package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	ip2location "github.com/ip2location/ip2location-go/v9"
	tbcontext "go.imperva.dev/toolbox/gin/context"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

var (
	// IPFilterErrorCodeHeader is the name of the header in which to save the specific error "code" (which is a
	// short string) if the middleware fails.
	IPFilterErrorCodeHeader = "X-Request-Error-Code"

	// IPFilterErrorMessageHeader is the name of the header in which to save the error message returned by a
	// middleware failure.
	IPFilterErrorMessageHeader = "X-Request-Error-Message"
)

// IPAddressRecord holds detailed information about an IP address.
type IPAddressRecord struct {
	// Address is the IP address.
	Address string

	// CountryCode is the two character country code based on ISO3166.
	CountryCode string

	// CountryName is the full country name based on ISO3166.
	CountryName string
}

// IPFilterOptions holds the options for configuring the IPFilter middleware.
type IPFilterOptions struct {
	// ClientIPLookupHandler is an optional handler used to determine the actual client IP in the request.
	//
	// If this field is nil, the given context's ClientIP() function is used.
	ClientIPLookupHandler func(*gin.Context) (string, error)

	// IPDBHandle is the handle to the IP location database used for lookups.
	//
	// You can use the LoadIPLocationDB() function to load the latest IP database file from
	// https://www.ip2location.com/.
	//
	// This field must NOT be nil.
	IPDBHandle *ip2location.DB

	// IsBannedHandler is called to determine if the request from the IP address, country or domain, repsectively,
	// should be blocked. It should return true or false and any error that occurs while performing the check.
	//
	// A handler allows for the most flexible scenario in how to store and manage IP/country/domain blacklists
	// such as querying a DB for every request or providing some caching capabilities, etc.
	//
	// It is up to the handler to output any error messages or banned response to the writer and set the appropriate
	// HTTP response code. If the handler returns false, middleware will stop processing.
	//
	// This field must NOT be nil.
	IsBannedHandler func(*gin.Context, IPAddressRecord) bool

	// ErrorHandler is called if an error occurs while executing the middleware.
	ErrorHandler ErrorHandler
}

// IPFilter determines whether or not a client making a request to the server has been blacklisted and should be
// prevented from accessing the requested resource.
//
// Because this middleware implements blacklisting, it's recommended that you include it as early as possible.
// However, be sure to include the Logger middleware before including this middleware if you wish to log messages
// using the current context's logger rather than the global logger.
//
// Use the IPFilter... global variables to change the default headers used by this middleware.
//
// If an error occurs, the IPFtilerErrorCodeHeader will be set and, if additional error details are available, the
// IPFilterErrorMessageHeader will contain the error message. The following error "codes" are used by this
// middleware for both the header and when calling the ErrorHandler, if one is supplied:
//
//  ◽ Failure while retrieving the client's IP address: client-ip-lookup-failure
//  ◽ Failure while retrieving the client IP's location information: ip-location-lookup-failure
//
// If an ErrorHandler is not supplied, the request will be aborted with the following HTTP status codes:
//
//  ◽ Failure while retrieving the client's IP address: 500
//  ◽ Failure while retrieving the client IP's location information: 500
//
// If an error handler is supplied, it is responsible for aborting the request or returning an appropriate
// response to the caller.
//
// The IsBannedHandler supplied in the options is responsible for aborting the request or returning an appropriate
// response to the caller if the IP address is blacklisted.
func IPFilter(options IPFilterOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := tbcontext.GetLogger(c)

		// first obtain the client's IP address
		clientIP := c.ClientIP()
		if options.ClientIPLookupHandler != nil {
			ip, err := options.ClientIPLookupHandler(c)
			if err != nil {
				errorCode := "client-ip-lookup-failure"
				c.Set(LocalizerErrorCodeHeader, errorCode)
				c.Set(LocalizerErrorMessageHeader, err.Error())
				logger.Error().Err(err).Msgf("failed to obtain client IP address: %s", err.Error())
				if options.ErrorHandler == nil {
					c.AbortWithStatus(http.StatusInternalServerError)
				} else if options.ErrorHandler(c, errorCode, err) {
					c.Next()
				}
				return
			}
			clientIP = ip
		}
		logger = logger.With().Str("client_ip", clientIP).Logger()

		// lookup information about the client IP from the database
		results, err := options.IPDBHandle.Get_all(clientIP)
		if err != nil {
			errorCode := "ip-location-lookup-failure"
			c.Set(LocalizerErrorCodeHeader, errorCode)
			c.Set(LocalizerErrorMessageHeader, err.Error())
			logger.Error().Err(err).Msgf("failed to retrieve client IP location information: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}

		// determine if the client should be blocked
		if ok := options.IsBannedHandler(c, IPAddressRecord{
			Address:     clientIP,
			CountryCode: results.Country_short,
			CountryName: results.Country_long,
		}); !ok {
			return
		}
		c.Next()
	}
}

// LoadIPLocationDB loads the binary-formatted (BIN) IP location database file downloaded from
// https://lite.ip2location.com/database/ip-country.
func LoadIPLocationDB(path string, ctx context.Context) (*ip2location.DB, error) {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("path", path).Logger()

	db, err := ip2location.OpenDB(path)
	if err != nil {
		e := &ErrLoadIPLocationDB{Path: path, Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return nil, e
	}
	return db, nil
}
