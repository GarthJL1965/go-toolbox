package i18n

import (
	"fmt"

	"github.com/go-playground/locales"
)

// Object error codes (1501-1750)
const (
	ErrKeyIsNotStringCode                       = 1501
	ErrUnknownTranslationCode                   = 1502
	ErrExistingTranslatorCode                   = 1503
	ErrConflictingTranslationCode               = 1504
	ErrRangeTranslationCode                     = 1505
	ErrOrdinalTranslationCode                   = 1506
	ErrCardinalTranslationCode                  = 1507
	ErrMissingPluralTranslationCode             = 1508
	ErrMissingBraceCode                         = 1509
	ErrBadParamSyntaxCode                       = 1510
	ErrLocaleNotRegisteredCode                  = 1511
	ErrInvalidRuleTypeCode                      = 1512
	ErrExportPathFailureCode                    = 1513
	ErrExportWriteFailureCode                   = 1514
	ErrImportPathFailureCode                    = 1515
	ErrImportReadFailureCode                    = 1516
	ErrRegisterValidationTranslationFailureCode = 1517
)

// ErrKeyIsNotString occurs when a translation key is not a string.
type ErrKeyIsNotString struct {
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrKeyIsNotString) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrKeyIsNotString) Error() string {
	return "translation key must be a string"
}

// Code returns the corresponding error code.
func (e *ErrKeyIsNotString) Code() int {
	return ErrKeyIsNotStringCode
}

// ErrUnknownTranslation occurs when an unknown translation key is supplied.
type ErrUnknownTranslation struct {
	Key string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrUnknownTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrUnknownTranslation) Error() string {
	return fmt.Sprintf("unknown translation key: %s", e.Key)
}

// Code returns the corresponding error code.
func (e *ErrUnknownTranslation) Code() int {
	return ErrUnknownTranslationCode
}

// ErrExistingTranslator occurs when there is a conflicting translator.
type ErrExistingTranslator struct {
	Locale string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrExistingTranslator) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrExistingTranslator) Error() string {
	return fmt.Sprintf("conflicting translator for locale '%s'", e.Locale)
}

// Code returns the corresponding error code.
func (e *ErrExistingTranslator) Code() int {
	return ErrExistingTranslatorCode
}

// ErrConflictingTranslation occurs when there is a conflicting translation.
type ErrConflictingTranslation struct {
	Locale string
	Key    string
	Rule   locales.PluralRule
	Text   string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrConflictingTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrConflictingTranslation) Error() string {
	return fmt.Sprintf("conflicting key '%s' rule '%s' with text '%s' for locale '%s', value being ignored",
		e.Key, e.Rule, e.Text, e.Locale)
}

// Code returns the corresponding error code.
func (e *ErrConflictingTranslation) Code() int {
	return ErrConflictingTranslationCode
}

// ErrRangeTranslation occurs when there is a range translation error.
type ErrRangeTranslation struct {
	Text string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrRangeTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrRangeTranslation) Error() string {
	return e.Text
}

// Code returns the corresponding error code.
func (e *ErrRangeTranslation) Code() int {
	return ErrRangeTranslationCode
}

// ErrOrdinalTranslation occurs when there is an ordinal translation error.
type ErrOrdinalTranslation struct {
	Text string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrOrdinalTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrOrdinalTranslation) Error() string {
	return e.Text
}

// Code returns the corresponding error code.
func (e *ErrOrdinalTranslation) Code() int {
	return ErrOrdinalTranslationCode
}

// ErrCardinalTranslation occurs when there is a cardinal translation error.
type ErrCardinalTranslation struct {
	Text string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrCardinalTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrCardinalTranslation) Error() string {
	return e.Text
}

// Code returns the corresponding error code.
func (e *ErrCardinalTranslation) Code() int {
	return ErrCardinalTranslationCode
}

// ErrMissingPluralTranslation occurs when there is a missing translation given the locales plural rules.
type ErrMissingPluralTranslation struct {
	Locale          string
	Key             string
	Rule            locales.PluralRule
	TranslationType string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrMissingPluralTranslation) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrMissingPluralTranslation) Error() string {
	return fmt.Sprintf("missing '%s' plural rule '%s' for translation with key '%s' and locale '%s'",
		e.TranslationType, e.Rule, e.Key, e.Locale)
}

// Code returns the corresponding error code.
func (e *ErrMissingPluralTranslation) Code() int {
	return ErrMissingPluralTranslationCode
}

// ErrMissingBrace occurs when there is a missing brace in a translation.
// eg. This is a {0 <-- missing ending '}'
type ErrMissingBrace struct {
	Locale string
	Key    interface{}
	Text   string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrMissingBrace) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrMissingBrace) Error() string {
	return fmt.Sprintf("missing brace ({}), in translation. locale: '%s' key: '%v' text: '%s'",
		e.Locale, e.Key, e.Text)
}

// Code returns the corresponding error code.
func (e *ErrMissingBrace) Code() int {
	return ErrMissingBraceCode
}

// ErrBadParamSyntax occurs when there is a bad parameter definition in a translation.
// eg. This is a {must-be-int}
type ErrBadParamSyntax struct {
	Locale string
	Param  string
	Key    string
	Text   string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrBadParamSyntax) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrBadParamSyntax) Error() string {
	return fmt.Sprintf(
		"bad parameter syntax, missing parameter '%s' in translation. locale: '%s' key: '%s' text: '%s'",
		e.Param, e.Locale, e.Key, e.Text)
}

// Code returns the corresponding error code.
func (e *ErrBadParamSyntax) Code() int {
	return ErrBadParamSyntaxCode
}

// ErrLocaleNotRegistered occurs when a local is not registered with the translator instance.
type ErrLocaleNotRegistered struct {
	Locale string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrLocaleNotRegistered) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrLocaleNotRegistered) Error() string {
	return fmt.Sprintf("locale '%s' is not registered.", e.Locale)
}

// Code returns the corresponding error code.
func (e *ErrLocaleNotRegistered) Code() int {
	return ErrLocaleNotRegisteredCode
}

// ErrInvalidRuleType occurs when an invalid rule type is detected in the translation file.
type ErrInvalidRuleType struct {
	RuleType string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrInvalidRuleType) InternalError() error {
	return nil
}

// Error returns the string version of the error.
func (e *ErrInvalidRuleType) Error() string {
	return fmt.Sprintf("rule type '%s' is not valid", e.RuleType)
}

// Code returns the corresponding error code.
func (e *ErrInvalidRuleType) Code() int {
	return ErrInvalidRuleTypeCode
}

// ErrExportPathFailure occurs when a failure is detected while creating the output path for exported trandlations.
type ErrExportPathFailure struct {
	Err  error
	Path string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrExportPathFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrExportPathFailure) Error() string {
	return fmt.Sprintf("failed to create export path '%s': %s", e.Path, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrExportPathFailure) Code() int {
	return ErrExportPathFailureCode
}

// ErrExportWriteFailure occurs when a failure is detected while writing exported translations.
type ErrExportWriteFailure struct {
	Err  error
	Path string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrExportWriteFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrExportWriteFailure) Error() string {
	return fmt.Sprintf("failed to export translations to '%s': %s", e.Path, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrExportWriteFailure) Code() int {
	return ErrExportWriteFailureCode
}

// ErrImportPathFailure occurs when a failure is detected while opening the file or folder for importing translations.
type ErrImportPathFailure struct {
	Err  error
	Path string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrImportPathFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrImportPathFailure) Error() string {
	return fmt.Sprintf("failed to create import path '%s': %s", e.Path, e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrImportPathFailure) Code() int {
	return ErrImportPathFailureCode
}

// ErrImportReadFailure occurs when a failure is detected while reading translations during import.
type ErrImportReadFailure struct {
	Err  error
	Path string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrImportReadFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrImportReadFailure) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to import translations from '%s': %s", e.Path, e.Err.Error())
	}
	return fmt.Sprintf("failed to import translations: %s", e.Err.Error())
}

// Code returns the corresponding error code.
func (e *ErrImportReadFailure) Code() int {
	return ErrImportReadFailureCode
}

// ErrRegisterValidationTranslationFailure occurs when a failure is detected while registering a validation tag's
// error message translation.
type ErrRegisterValidationTranslationFailure struct {
	Err    error
	Tag    string
	Locale string
}

// InternalError returns the internal standard error object if there is one or nil if none is set.
func (e *ErrRegisterValidationTranslationFailure) InternalError() error {
	return e.Err
}

// Error returns the string version of the error.
func (e *ErrRegisterValidationTranslationFailure) Error() string {
	return fmt.Sprintf("failed to register translation for validation tag '%s': %s (locale: %s)", e.Tag,
		e.Err.Error(), e.Locale)
}

// Code returns the corresponding error code.
func (e *ErrRegisterValidationTranslationFailure) Code() int {
	return ErrRegisterValidationTranslationFailureCode
}
