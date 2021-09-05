package i18n

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-playground/locales"
	"go.imperva.dev/zerolog"
	"go.imperva.dev/zerolog/log"
)

const (
	RuleTypePlain    = "plain"
	RuleTypeCardinal = "cardinal"
	RuleTypeOrdinal  = "ordinal"
	RuleTypeRange    = "range"
)

type translation struct {
	Description      string `toml:"description,omitempty"`
	Locale           string `toml:"locale"`
	OverrideExisting bool   `toml:"override,omitempty"`
	RuleType         string `toml:"type,omitempty"`
	Zero             string `toml:"zero,omitempty"`
	One              string `toml:"one,omitempty"`
	Two              string `toml:"two,omitempty"`
	Few              string `toml:"few,omitempty"`
	Many             string `toml:"many,omitempty"`
	Other            string `toml:"other"`
}
type translations map[string]*translation

// Export writes the translations out to a directory.
//
// Each locale is written to its own file called <locale>.toml in the given directory.
//
// The following errors are returned by this function:
// ErrExportPathFailure, ErrKeyIsNotString, ExportWriteFailure
func (ut *UniversalTranslator) Export(path string, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("path", path).Logger()

	// create the folder if it doesn't exist already
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			e := &ErrExportPathFailure{Err: err, Path: path}
			logger.Error().Err(e.Err).Msg(e.Error())
			return e
		}
		if err = os.MkdirAll(path, 0755); err != nil {
			e := &ErrExportPathFailure{Err: err, Path: path}
			logger.Error().Err(e.Err).Msg(e.Error())
			return e
		}
	}

	// export each locale
	for _, locale := range ut.translators {
		// build translations for the locale
		trans := translations{}
		l := locale.Locale()
		cl := logger.With().Str("locale", l).Logger()
		cl.Debug().Msgf("exporting locale: %s", l)
		for k, v := range locale.(*translator).translations {
			key, ok := k.(string)
			if !ok {
				return &ErrKeyIsNotString{}
			}
			if _, ok := trans[key]; !ok {
				trans[key] = &translation{}
			}
			trans[key].Locale = l
			trans[key].Other = v.text
		}
		if err := ut.exportPlurals(trans, l, RuleTypeCardinal, locale.(*translator).cardinalTanslations,
			ctx); err != nil {

			return err
		}
		if err := ut.exportPlurals(trans, l, RuleTypeOrdinal, locale.(*translator).ordinalTanslations,
			ctx); err != nil {

			return err
		}
		if err := ut.exportPlurals(trans, l, RuleTypeRange, locale.(*translator).rangeTanslations, ctx); err != nil {
			return err
		}

		// write the translations to the TOML file
		buf := new(bytes.Buffer)
		if err := toml.NewEncoder(buf).Encode(trans); err != nil {
			return &ErrExportWriteFailure{Path: path, Err: err}
		}
		file := filepath.Join(path, fmt.Sprintf("%s.toml", l))
		cl.Debug().Str("file", file).Msgf("writing translation file: %s", file)
		if err := ioutil.WriteFile(file, buf.Bytes(), 0644); err != nil {
			return &ErrExportWriteFailure{Path: path, Err: err}
		}
	}
	return nil
}

// Import reads the translations out of a file or directory on disk.
//
// If the path is a directory, any .toml files located in the directory will be imported.
//
// The following errors are returned by this function:
// ErrImportPathFailure, any error from the ImportFromReader() function
func (ut *UniversalTranslator) Import(path string, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}
	logger = logger.With().Str("path", path).Logger()

	fi, err := os.Stat(path)
	if err != nil {
		e := &ErrImportPathFailure{Path: path, Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}

	// declare the function that will be called to process a file
	processFn := func(filename string) error {
		l := logger.With().Str("file", filename).Logger()

		l.Debug().Msgf("loading translation file: %s", filename)
		f, err := os.Open(filename)
		if err != nil {
			e := &ErrImportPathFailure{Path: path, Err: err}
			l.Error().Err(e.Err).Msg(e.Error())
			return e
		}
		defer f.Close()
		if err := ut.ImportFromReader(f, ctx); err != nil {
			var e *ErrImportReadFailure
			if errors.As(err, &e) {
				e.Path = path
				return e
			}
			return err
		}
		return nil
	}

	// just read the file
	if !fi.IsDir() {
		return processFn(path)
	}

	// read .toml files within the directory
	walker := func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) != ".toml" {
			return nil
		}
		return processFn(p)
	}
	return filepath.Walk(path, walker)
}

// ImportFromReader imports the the translations found within the contents read from the supplied reader.
//
// The following errors are returned by this function:
// ErrImportReadFailure, ErrLocaleNotRegistered, ErrInvalidRuleType, any error from the translator's Add(),
// AddCardinal(), AddOrdinal() or AddRange() functions
func (ut *UniversalTranslator) ImportFromReader(reader io.Reader, ctx context.Context) error {
	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	// unmarshal the data
	trans := translations{}
	if _, err := toml.NewDecoder(reader).Decode(&trans); err != nil {
		e := &ErrImportReadFailure{Err: err}
		logger.Error().Err(e.Err).Msg(e.Error())
		return e
	}

	// add each translation found in the reader
	for key, t := range trans {
		locale, found := ut.FindTranslator(t.Locale)
		if !found {
			e := &ErrLocaleNotRegistered{Locale: t.Locale}
			logger.Error().Err(e).Msg(e.Error())
			return e
		}
		logger.Debug().Str("locale", t.Locale).Msgf("importing translations for locale: %s", t.Locale)

		// parse the type of rule
		var addFn func(interface{}, string, locales.PluralRule, bool) error
		switch strings.ToLower(t.RuleType) {
		case "", RuleTypePlain:
			if err := locale.Add(key, t.Other, t.OverrideExisting); err != nil {
				return err
			}
			continue
		case RuleTypeCardinal:
			addFn = locale.AddCardinal
		case RuleTypeOrdinal:
			addFn = locale.AddOrdinal
		case RuleTypeRange:
			addFn = locale.AddRange
		default:
			e := &ErrInvalidRuleType{RuleType: t.RuleType}
			logger.Error().Err(e).Msg(e.Error())
			return e
		}

		// add the translations
		if t.Zero != "" {
			if err := addFn(key, t.Zero, locales.PluralRuleZero, t.OverrideExisting); err != nil {
				return err
			}
		}
		if t.One != "" {
			if err := addFn(key, t.One, locales.PluralRuleOne, t.OverrideExisting); err != nil {
				return err
			}
		}
		if t.Two != "" {
			if err := addFn(key, t.Two, locales.PluralRuleTwo, t.OverrideExisting); err != nil {
				return err
			}
		}
		if t.Few != "" {
			if err := addFn(key, t.Few, locales.PluralRuleFew, t.OverrideExisting); err != nil {
				return err
			}
		}
		if t.Many != "" {
			if err := addFn(key, t.Many, locales.PluralRuleMany, t.OverrideExisting); err != nil {
				return err
			}
		}
		if t.Other != "" {
			if err := addFn(key, t.Other, locales.PluralRuleOther, t.OverrideExisting); err != nil {
				return err
			}
		}
	}

	return nil
}

// exportPlurals exports the translations associated with the given locale and rule type.
//
// The following errors are returned by this function:
// ErrKeyIsNotString
func (ut *UniversalTranslator) exportPlurals(trans translations, locale, ruleType string,
	plurals map[interface{}][]*transText, ctx context.Context) error {

	logger := log.Logger
	if l := zerolog.Ctx(ctx); l != nil {
		logger = *l
	}

	for k, pluralTrans := range plurals {
		key, ok := k.(string)
		if !ok {
			e := &ErrKeyIsNotString{}
			logger.Error().Err(e).Msg(e.Error())
			return e
		}
		if _, ok := trans[key]; !ok {
			trans[key] = &translation{}
		}

		for i, plural := range pluralTrans {
			if plural == nil {
				continue
			}
			trans[key].Locale = locale
			trans[key].RuleType = ruleType
			switch strings.ToLower(locales.PluralRule(i).String()) {
			case "zero":
				trans[key].Zero = plural.text
			case "one":
				trans[key].One = plural.text
			case "two":
				trans[key].Two = plural.text
			case "few":
				trans[key].Few = plural.text
			case "many":
				trans[key].Many = plural.text
			case "other":
				trans[key].Other = plural.text
			}
		}
	}
	return nil
}
