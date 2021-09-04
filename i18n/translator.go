package i18n

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-playground/locales"
	ut "github.com/go-playground/universal-translator"
)

const (
	paramZero          = "{0}"
	paramOne           = "{1}"
	unknownTranslation = ""
)

var _ ut.Translator = new(translator)
var _ locales.Translator = new(translator)

type translator struct {
	locales.Translator
	translations map[interface{}]*transText
	// array index is mapped to locales.PluralRule index + the locales.PluralRuleUnknown
	cardinalTanslations map[interface{}][]*transText
	ordinalTanslations  map[interface{}][]*transText
	rangeTanslations    map[interface{}][]*transText
}

type transText struct {
	text    string
	indexes []int
}

func newTranslator(trans locales.Translator) ut.Translator {
	return &translator{
		Translator:   trans,
		translations: make(map[interface{}]*transText),
		// translation text broken up by byte index
		cardinalTanslations: make(map[interface{}][]*transText),
		ordinalTanslations:  make(map[interface{}][]*transText),
		rangeTanslations:    make(map[interface{}][]*transText),
	}
}

// Add adds a normal translation for a particular language/locale.
//
// {#} is the only replacement type accepted and are ad infinitum.
//
// Example: one: '{0} day left', other: '{0} days left'
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrConflictingTranslation, ErrMissingBrace, ErrBadParamSyntax
func (t *translator) Add(k interface{}, text string, override bool) error {
	key, ok := k.(string)
	if !ok {
		return &ErrKeyIsNotString{}
	}

	if _, ok := t.translations[key]; ok && !override {
		return &ErrConflictingTranslation{Locale: t.Locale(), Key: key, Text: text}
	}

	lb := strings.Count(text, "{")
	rb := strings.Count(text, "}")

	if lb != rb {
		return &ErrMissingBrace{Locale: t.Locale(), Key: key, Text: text}
	}

	trans := &transText{
		text: text,
	}

	var idx int

	for i := 0; i < lb; i++ {
		s := "{" + strconv.Itoa(i) + "}"
		idx = strings.Index(text, s)
		if idx == -1 {
			return &ErrBadParamSyntax{Locale: t.Locale(), Param: s, Key: key, Text: text}
		}

		trans.indexes = append(trans.indexes, idx)
		trans.indexes = append(trans.indexes, idx+len(s))
	}

	t.translations[key] = trans

	return nil
}

// AddCardinal adds a cardinal plural translation for a particular language/locale.
//
// {0} is the only replacement type accepted and only one variable is accepted as multiple cannot be used for a plural
// rule determination, unless it is a range (see AddRange() function).
//
// Example: one: '{0} day left', other: '{0} days left'
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrCardinalTranslation, ErrConflictingTranslation
func (t *translator) AddCardinal(k interface{}, text string, rule locales.PluralRule, override bool) error {
	key, ok := k.(string)
	if !ok {
		return &ErrKeyIsNotString{}
	}

	var verified bool

	// verify plural rule exists for locale
	for _, pr := range t.PluralsCardinal() {
		if pr == rule {
			verified = true
			break
		}
	}

	if !verified {
		return &ErrCardinalTranslation{
			Text: fmt.Sprintf("cardinal plural rule '%s' does not exist for locale '%s' key: '%v' text: '%s'",
				rule, t.Locale(), key, text),
		}
	}

	tarr, ok := t.cardinalTanslations[key]
	if ok {
		// verify not adding a conflicting record
		if len(tarr) > 0 && tarr[rule] != nil && !override {
			return &ErrConflictingTranslation{Locale: t.Locale(), Key: key, Rule: rule, Text: text}
		}

	} else {
		tarr = make([]*transText, 7)
		t.cardinalTanslations[key] = tarr
	}

	trans := &transText{
		text:    text,
		indexes: make([]int, 2),
	}

	tarr[rule] = trans

	idx := strings.Index(text, paramZero)
	if idx == -1 {
		tarr[rule] = nil
		return &ErrCardinalTranslation{
			Text: fmt.Sprintf("parameter '%s' not found, may want to use 'Add' instead of 'AddCardinal'. "+
				"locale: '%s' key: '%v' text: '%s'", paramZero, t.Locale(), key, text),
		}
	}

	trans.indexes[0] = idx
	trans.indexes[1] = idx + len(paramZero)

	return nil
}

// AddOrdinal adds an ordinal plural translation for a particular language/locale.
//
// {0} is the only replacement type accepted and only one variable is accepted as multiple cannot be used for a plural
// rule determination, unless it is a range (see AddRange() function).
//
// Example: one: '{0}st day of spring', two: '{0}nd day of spring', few: '{0}rd day of spring', ...
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrOrdinalTranslation, ErrConflictingTranslation
func (t *translator) AddOrdinal(k interface{}, text string, rule locales.PluralRule, override bool) error {
	key, ok := k.(string)
	if !ok {
		return &ErrKeyIsNotString{}
	}

	var verified bool

	// verify plural rule exists for locale
	for _, pr := range t.PluralsOrdinal() {
		if pr == rule {
			verified = true
			break
		}
	}

	if !verified {
		return &ErrOrdinalTranslation{
			Text: fmt.Sprintf("ordinal plural rule '%s' does not exist for locale '%s' key: '%v' text: '%s'",
				rule, t.Locale(), key, text),
		}
	}

	tarr, ok := t.ordinalTanslations[key]
	if ok {
		// verify not adding a conflicting record
		if len(tarr) > 0 && tarr[rule] != nil && !override {
			return &ErrConflictingTranslation{Locale: t.Locale(), Key: key, Rule: rule, Text: text}
		}

	} else {
		tarr = make([]*transText, 7)
		t.ordinalTanslations[key] = tarr
	}

	trans := &transText{
		text:    text,
		indexes: make([]int, 2),
	}

	tarr[rule] = trans

	idx := strings.Index(text, paramZero)
	if idx == -1 {
		tarr[rule] = nil
		return &ErrOrdinalTranslation{
			Text: fmt.Sprintf("parameter '%s' not found, may want to use 'Add' instead of 'AddOrdinal'. "+
				"locale: '%s' key: '%v' text: '%s'", paramZero, t.Locale(), key, text),
		}
	}

	trans.indexes[0] = idx
	trans.indexes[1] = idx + len(paramZero)

	return nil
}

// AddRange adds a range plural translation for a particular language/locale.
//
// {0} and {1} are the only replacement types accepted and only these are accepted.
//
// Example: other: '{0}-{1} days left'
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrRangeTranslation, ErrConflictingTranslation
func (t *translator) AddRange(k interface{}, text string, rule locales.PluralRule, override bool) error {
	key, ok := k.(string)
	if !ok {
		return &ErrKeyIsNotString{}
	}

	var verified bool

	// verify plural rule exists for locale
	for _, pr := range t.PluralsRange() {
		if pr == rule {
			verified = true
			break
		}
	}

	if !verified {
		return &ErrRangeTranslation{
			Text: fmt.Sprintf("range plural rule '%s' does not exist for locale '%s' key: '%v' text: '%s'",
				rule, t.Locale(), key, text),
		}
	}

	tarr, ok := t.rangeTanslations[key]
	if ok {
		// verify not adding a conflicting record
		if len(tarr) > 0 && tarr[rule] != nil && !override {
			return &ErrConflictingTranslation{Locale: t.Locale(), Key: key, Rule: rule, Text: text}
		}

	} else {
		tarr = make([]*transText, 7)
		t.rangeTanslations[key] = tarr
	}

	trans := &transText{
		text:    text,
		indexes: make([]int, 4),
	}

	tarr[rule] = trans

	idx := strings.Index(text, paramZero)
	if idx == -1 {
		tarr[rule] = nil
		return &ErrRangeTranslation{
			Text: fmt.Sprintf("parameter '%s' not found, are you sure you're adding a Range Translation? "+
				" locale: '%s' key: '%v' text: '%s'", paramZero, t.Locale(), key, text),
		}
	}

	trans.indexes[0] = idx
	trans.indexes[1] = idx + len(paramZero)

	idx = strings.Index(text, paramOne)
	if idx == -1 {
		tarr[rule] = nil
		return &ErrRangeTranslation{Text: fmt.Sprintf("parameter '%s' not found, a Range Translation requires two parameters. locale: '%s' key: '%v' text: '%s'", paramOne, t.Locale(), key, text)}
	}

	trans.indexes[2] = idx
	trans.indexes[3] = idx + len(paramOne)

	return nil
}

// T creates the translation for the locale given the 'key' and params passed in.
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrUnknownTranslation
func (t *translator) T(k interface{}, params ...string) (string, error) {
	key, ok := k.(string)
	if !ok {
		return unknownTranslation, &ErrKeyIsNotString{}
	}

	trans, ok := t.translations[key]
	if !ok {
		return unknownTranslation, &ErrUnknownTranslation{Key: key}
	}

	b := make([]byte, 0, 64)

	var start, end, count int

	for i := 0; i < len(trans.indexes); i++ {
		end = trans.indexes[i]
		b = append(b, trans.text[start:end]...)
		b = append(b, params[count]...)
		i++
		start = trans.indexes[i]
		count++
	}

	b = append(b, trans.text[start:]...)

	return string(b), nil
}

// C creates the cardinal translation for the locale given the 'key', 'num' and 'digit' arguments and param passed in.
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrUnknownTranslation
func (t *translator) C(k interface{}, num float64, digits uint64, param string) (string, error) {
	key, ok := k.(string)
	if !ok {
		return unknownTranslation, &ErrKeyIsNotString{}
	}

	tarr, ok := t.cardinalTanslations[key]
	if !ok {
		return unknownTranslation, &ErrUnknownTranslation{Key: key}
	}

	rule := t.CardinalPluralRule(num, digits)

	trans := tarr[rule]

	b := make([]byte, 0, 64)
	b = append(b, trans.text[:trans.indexes[0]]...)
	b = append(b, param...)
	b = append(b, trans.text[trans.indexes[1]:]...)

	return string(b), nil
}

// O creates the ordinal translation for the locale given the 'key', 'num' and 'digit' arguments and param passed in.
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrUnknownTranslation
func (t *translator) O(k interface{}, num float64, digits uint64, param string) (string, error) {
	key, ok := k.(string)
	if !ok {
		return unknownTranslation, &ErrKeyIsNotString{}
	}

	tarr, ok := t.ordinalTanslations[key]
	if !ok {
		return unknownTranslation, &ErrUnknownTranslation{Key: key}
	}

	rule := t.OrdinalPluralRule(num, digits)

	trans := tarr[rule]

	b := make([]byte, 0, 64)
	b = append(b, trans.text[:trans.indexes[0]]...)
	b = append(b, param...)
	b = append(b, trans.text[trans.indexes[1]:]...)

	return string(b), nil
}

// R creates the range translation for the locale given the 'key', 'num1', 'digit1', 'num2' and 'digit2' arguments
// and 'param1' and 'param2' passed in.
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrUnknownTranslation
func (t *translator) R(k interface{}, num1 float64, digits1 uint64, num2 float64, digits2 uint64, param1, param2 string) (string, error) {
	key, ok := k.(string)
	if !ok {
		return unknownTranslation, &ErrKeyIsNotString{}
	}

	tarr, ok := t.rangeTanslations[key]
	if !ok {
		return unknownTranslation, &ErrUnknownTranslation{Key: key}
	}

	rule := t.RangePluralRule(num1, digits1, num2, digits2)

	trans := tarr[rule]

	b := make([]byte, 0, 64)
	b = append(b, trans.text[:trans.indexes[0]]...)
	b = append(b, param1...)
	b = append(b, trans.text[trans.indexes[1]:trans.indexes[2]]...)
	b = append(b, param2...)
	b = append(b, trans.text[trans.indexes[3]:]...)

	return string(b), nil
}

// VerifyTranslations checks to ensures that no plural rules have been missed within the translations.
//
// The following errors are returned by this function:
// ErrKeyIsNotString, ErrMissingPluralTranslation
func (t *translator) VerifyTranslations() error {

	for k, v := range t.cardinalTanslations {
		key, ok := k.(string)
		if !ok {
			return &ErrKeyIsNotString{}
		}

		for _, rule := range t.PluralsCardinal() {

			if v[rule] == nil {
				return &ErrMissingPluralTranslation{
					Locale:          t.Locale(),
					TranslationType: "plural",
					Rule:            rule,
					Key:             key,
				}
			}
		}
	}

	for k, v := range t.ordinalTanslations {
		key, ok := k.(string)
		if !ok {
			return &ErrKeyIsNotString{}
		}

		for _, rule := range t.PluralsOrdinal() {

			if v[rule] == nil {
				return &ErrMissingPluralTranslation{
					Locale:          t.Locale(),
					TranslationType: "ordinal",
					Rule:            rule,
					Key:             key,
				}
			}
		}
	}

	for k, v := range t.rangeTanslations {
		key, ok := k.(string)
		if !ok {
			return &ErrKeyIsNotString{}
		}

		for _, rule := range t.PluralsRange() {

			if v[rule] == nil {
				return &ErrMissingPluralTranslation{
					Locale:          t.Locale(),
					TranslationType: "range",
					Rule:            rule,
					Key:             key,
				}
			}
		}
	}

	return nil
}
