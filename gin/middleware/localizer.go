package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	ut "github.com/go-playground/universal-translator"
	"go.imperva.dev/toolbox/gin/context"
	"go.imperva.dev/toolbox/i18n"
	"golang.org/x/text/language"
)

// LocalizerOptions holds the options for configuring the Localizer middleware.
type LocalizerOptions struct {
	// Translator is the main translation object which stores the list of supported languages.
	//
	// This field must NOT be nil.
	Translator *i18n.UniversalTranslator

	// EnableErrorCodeHeader indicates whether or not to set the custom X-*-Error-Code header if an error occurs.
	EnableErrorCodeHeader bool

	// EnableErrorMessageHeader indicates whether or not to set the custom X-*-Error-Message header if an error
	// occurs.
	EnableErrorMessageHeader bool

	// ErrorHandler is called if an error occurs while executing the middleware.
	ErrorHandler ErrorHandler
}

// GetErrorCodeHeader returns the name of the X header to use for holding the middleware's error code.
func (o LocalizerOptions) GetErrorCodeHeader() string {
	return "X-Localizer-Error-Code"
}

// GetErrorMessageHeader returns the name of the X header to use for holding the middleware's error message.
func (o LocalizerOptions) GetErrorMessageHeader() string {
	return "X-Localizer-Limiter-Error-Message"
}

// SetErrorCodeHeader returns whether or not to set the error code header when an error occurs.
func (o LocalizerOptions) SetErrorCodeHeader() bool {
	return o.EnableErrorCodeHeader
}

// SetErrorMessageHeader returns whether or not to set the error code message when an error occurs.
func (o LocalizerOptions) SetErrorMessageHeader() bool {
	return o.EnableErrorMessageHeader
}

// Localizer reads the "lang" query parameter and the Accept-Language header to determine which language translation
// engine will be stored in the context for later use in translating messages.
//
// Your application must first create a new translator by calling the i18n.NewUniversalTranslator() function, loading
// any translations from files or defining them specifically through function calls and then calling the
// VerifyTranslations() function on the instance to ensure everything is working. Pass that translator object in the
// options.
//
// Use the Localizer... global variables to change the default headers used by this middleware.
//
// If an error occurs, the LocalizerErrorCodeHeader will be set and, if additional error details are available, the
// LocalizerErrorMessageHeader will contain the error message. The following error "codes" are used by this
// middleware for both the header and when calling the ErrorHandler, if one is supplied:
//
//  ◽ Failure while retrieving parsing the Accept-Language header: parse-accept-language-failure
//
// If an ErrorHandler is not supplied, the request will be aborted with the following HTTP status codes:
//
//  ◽ Failure while retrieving parsing the Accept-Language header: 500
//
// If an error handler is supplied, it is responsible for aborting the request or returning an appropriate
// response to the caller.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func Localizer(options LocalizerOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := context.GetLogger(c)

		// build the list of requested languages in order of precedence
		langs := []string{c.Request.FormValue("lang")}
		tags, _, err := language.ParseAcceptLanguage(c.Request.Header.Get("Accept-Language"))
		if err != nil {
			errorCode := "parse-accept-language-failure"
			setErrorHeaders(c, options, errorCode, err)
			logger.Error().Err(err).Msgf("failed to parse Accept-Language header: %s", err.Error())
			if options.ErrorHandler == nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else if options.ErrorHandler(c, errorCode, err) {
				c.Next()
			}
			return
		}
		for _, t := range tags {
			langs = append(langs, t.String())
		}

		// attempt to find a translator for the requested languages, falling back to the translator's default
		// language if none are found
		var trans ut.Translator
		var found bool
		for _, lang := range langs {
			trans, found = options.Translator.GetTranslator(lang)
			if found {
				break
			}
		}

		// save the translator
		c.Set(context.KeyTranslator, trans)

		c.Next()
	}
}
