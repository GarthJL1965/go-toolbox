package i18n

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-playground/locales"
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
func (ut *UniversalTranslator) Export(path string) error {
	// create the folder if it doesn't exist already
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}

	// export each locale
	for _, locale := range ut.translators {
		// build translations for the locale
		trans := translations{}
		l := locale.Locale()
		for k, v := range locale.(*translator).translations {
			key, ok := k.(string)
			if !ok {
				return errors.New("translation key is not a string")
			}
			if _, ok := trans[key]; !ok {
				trans[key] = &translation{}
			}
			trans[key].Locale = l
			trans[key].Other = v.text
		}
		if err := ut.exportPlurals(trans, l, RuleTypeCardinal, locale.(*translator).cardinalTanslations); err != nil {
			return err
		}
		if err := ut.exportPlurals(trans, l, RuleTypeOrdinal, locale.(*translator).ordinalTanslations); err != nil {
			return err
		}
		if err := ut.exportPlurals(trans, l, RuleTypeRange, locale.(*translator).rangeTanslations); err != nil {
			return err
		}

		// write the translations to the TOML file
		buf := new(bytes.Buffer)
		if err := toml.NewEncoder(buf).Encode(trans); err != nil {
			return err
		}
		if err := ioutil.WriteFile(filepath.Join(path, fmt.Sprintf("%s.toml", locale.Locale())),
			buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return nil
}

// Import reads the translations out of a file or directory on disk.
//
// If the path is a directory, any .toml files located in the directory will be imported.
func (ut *UniversalTranslator) Import(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	// declare the function that will be called to process a file
	processFn := func(filename string) error {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		return ut.ImportFromReader(f)
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
func (ut *UniversalTranslator) ImportFromReader(reader io.Reader) error {
	// unmarshal the data
	trans := translations{}
	if _, err := toml.NewDecoder(reader).Decode(&trans); err != nil {
		return err
	}

	// add each translation found in the reader
	for key, t := range trans {
		locale, found := ut.FindTranslator(t.Locale)
		if !found {
			return &ErrMissingLocale{locale: t.Locale}
		}

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
			return &ErrBadRuleType{ruleType: t.RuleType}
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

func (ut *UniversalTranslator) exportPlurals(trans translations, locale, ruleType string,
	plurals map[interface{}][]*transText) error {

	for k, pluralTrans := range plurals {
		key, ok := k.(string)
		if !ok {
			return errors.New("translation key is not a string")
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
