package errors_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/go-playground/locales/en"
	"go.impervaunity.io/pkg/toolbox/i18n"
)

func TestExtendedError(t *testing.T) {
	en := en.New()
	ut := i18n.NewUniversalTranslator(en, en)
	trans, _ := ut.GetTranslator("en")
	if err := trans.Add(1, "some text", false); err != nil {
		if errors.Is(err, new(i18n.ErrKeyIsNotString)) {
			t.Logf("errors.Is(): confirmed to be ErrKeyIsNotString")
		} else {
			t.Errorf("errors.Is(): error not ErrKeyIsNotString but rather: %s", reflect.TypeOf(err))
		}

		var e *i18n.ErrKeyIsNotString
		if errors.As(err, &e) {
			t.Logf("errors.As(): cast as ErrKeyIsNotString")
		} else {
			t.Errorf("errors.As(): error not ErrKeyIsNotString but rather: %s", reflect.TypeOf(err))
		}

		if e, ok := err.(*i18n.ErrKeyIsNotString); ok {
			if e.Code() == i18n.ErrKeyIsNotStringCode {
				t.Logf("Code(): confirmed to be ErrKeyIsNotStringCode")
			} else {
				t.Errorf("Code(): does not match KeyIsNotStringCode %d but is: %d",
					i18n.ErrKeyIsNotStringCode, e.Code())
			}
		} else {
			t.Errorf("type assertion: error not ErrKeyIsNotString but rather: %s", reflect.TypeOf(err))
		}
	}
}
