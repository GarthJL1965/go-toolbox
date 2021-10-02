package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	ut "github.com/go-playground/universal-translator"
	"go.imperva.dev/toolbox/gin/context"
	"go.imperva.dev/toolbox/i18n"
	"golang.org/x/text/language"
)

var (
	// LocalizerErrorCodeHeader is the name of the header in which to save the specific error "code" (which is a
	// short string) if the middleware fails.
	LocalizerErrorCodeHeader = "X-Request-Error-Code"

	// LocalizerErrorMessageHeader is the name of the header in which to save the error message returned by a
	// middleware failure.
	LocalizerErrorMessageHeader = "X-Request-Error-Message"
)

// LocalizerOptions holds the options for configuring the Localizer middleware.
type LocalizerOptions struct {
	// Translator is the main translation object which stores the list of supported languages.
	//
	// This field must NOT be nil.
	Translator *i18n.UniversalTranslator

	// ErrorHandler is called if an error occurs while executing the middleware.
	ErrorHandler ErrorHandler
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
			c.Set(LocalizerErrorCodeHeader, errorCode)
			c.Set(LocalizerErrorMessageHeader, err.Error())
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
