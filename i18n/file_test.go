package i18n_test

import (
	"context"
	"testing"

	"github.com/go-playground/locales"
	"github.com/go-playground/locales/en"
	"go.imperva.dev/toolbox/i18n"
)

func TestImportFile(t *testing.T) {
	ctx := context.TODO()

	// load translations
	en := en.New()
	ut := i18n.NewUniversalTranslator(en, en)
	if err := ut.Import("./examples/en.toml", ctx); err != nil {
		t.Errorf("error while importing TOML file: %s", err.Error())
	}

	// verify translations
	if err := ut.VerifyTranslations(); err != nil {
		t.Errorf("error while verifying translations: %s", err.Error())
	}

	// test a message
	translator, ok := ut.GetTranslator("en")
	if !ok {
		t.Errorf("translator 'en' not found")
	}
	str, err := translator.T("plain-message")
	if err != nil {
		t.Errorf("failed to translate message: %s", err.Error())
	}
	t.Logf("translated message: %s", str)
}

func TestExportFile(t *testing.T) {
	ctx := context.TODO()

	// load translations
	en := en.New()
	ut := i18n.NewUniversalTranslator(en, en)

	// add english translations
	translator, ok := ut.GetTranslator("en")
	if !ok {
		t.Errorf("translator 'en' not found")
	}
	if err := translator.Add("simple-message", "this is some text to output", false); err != nil {
		t.Errorf("failed to add simple message: %s", err.Error())
	}
	if err := translator.AddOrdinal("ordinal-message", "this is your {0}th day", locales.PluralRuleOther, false); err != nil {
		t.Errorf("failed to add ordinal message: %s", err.Error())
	}
	if err := translator.AddOrdinal("ordinal-message", "this is your {0}st day", locales.PluralRuleOne, false); err != nil {
		t.Errorf("failed to add ordinal message: %s", err.Error())
	}
	if err := translator.AddOrdinal("ordinal-message", "this is your {0}nd day", locales.PluralRuleTwo, false); err != nil {
		t.Errorf("failed to add ordinal message: %s", err.Error())
	}
	if err := translator.AddOrdinal("ordinal-message", "this is your {0}rd day", locales.PluralRuleFew, true); err != nil {
		t.Errorf("failed to add ordinal message: %s", err.Error())
	}

	// verify translations
	if err := ut.VerifyTranslations(); err != nil {
		t.Errorf("error while verifying translations: %s", err.Error())
	}

	// export messages
	if err := ut.Export("./examples/out", ctx); err != nil {
		t.Errorf("failed to export translations: %s", err.Error())
	}
	t.Logf("exported translations to ./examples/out")
}
