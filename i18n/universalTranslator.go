package i18n

import (
	"context"
	"strings"

	"github.com/go-playground/locales"
	ut "github.com/go-playground/universal-translator"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

// UniversalTranslator holds all locale & translation data.
type UniversalTranslator struct {
	translators map[string]ut.Translator
	fallback    ut.Translator
}

// New returns a new UniversalTranslator instance set with the fallback locale and locales it should support.
func NewUniversalTranslator(fallback locales.Translator,
	supportedLocales ...locales.Translator) *UniversalTranslator {

	t := &UniversalTranslator{
		translators: make(map[string]ut.Translator),
	}

	for _, v := range supportedLocales {

		trans := newTranslator(v)
		t.translators[strings.ToLower(trans.Locale())] = trans

		if fallback.Locale() == v.Locale() {
			t.fallback = trans
		}
	}

	if t.fallback == nil && fallback != nil {
		t.fallback = newTranslator(fallback)
	}

	return t
}

// FindTranslator trys to find a Translator based on an array of locales and returns the first one it can find,
// otherwise returns the fallback translator.
func (t *UniversalTranslator) FindTranslator(locales ...string) (trans ut.Translator, found bool) {

	for _, locale := range locales {

		if trans, found = t.translators[strings.ToLower(locale)]; found {
			return
		}
	}

	return t.fallback, false
}

// GetTranslator returns the specified translator for the given locale or fallback if not found.
func (t *UniversalTranslator) GetTranslator(locale string) (trans ut.Translator, found bool) {

	if trans, found = t.translators[strings.ToLower(locale)]; found {
		return
	}

	return t.fallback, false
}

// GetFallback returns the fallback locale.
func (t *UniversalTranslator) GetFallback() ut.Translator {
	return t.fallback
}

// AddTranslator adds the supplied translator.
//
// If it already exists the override param will be checked and if false an error will be returned. Otherwise the
// translator will be overridden. If the fallback matches the supplied translator, it will be overridden as well.
// NOTE: This is normally only used when translator is embedded within a library.
//
// The following errors are returned by this function:
// ErrExistingTranslator
func (t *UniversalTranslator) AddTranslator(translator locales.Translator, override bool, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	lc := strings.ToLower(translator.Locale())
	logger = logger.With().Str("locale", translator.Locale()).Logger()

	_, ok := t.translators[lc]
	if ok && !override {
		e := &ErrExistingTranslator{Locale: translator.Locale()}
		logger.Error().Err(e).Msg(e.Error())
		return e
	}

	trans := newTranslator(translator)

	if t.fallback.Locale() == translator.Locale() {

		// because it's optional to have a fallback, I don't impose that limitation
		// don't know why you wouldn't but...
		if !override {
			e := &ErrExistingTranslator{Locale: translator.Locale()}
			logger.Error().Err(e).Msg(e.Error())
			return e
		}

		t.fallback = trans
	}

	t.translators[lc] = trans

	return nil
}

// VerifyTranslations runs through all locales and identifies any issues.
//
// The following errors are returned by this function:
// any error from the translator's VerifyTranslations() function
func (t *UniversalTranslator) VerifyTranslations() (err error) {

	for _, trans := range t.translators {
		err = trans.VerifyTranslations()
		if err != nil {
			return
		}
	}

	return
}
