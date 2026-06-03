package oauth

import (
	"errors"
	"net/http"
	"regexp"

	"cattlecloud.net/go/forms"
	"github.com/shoenig/go-conceal"
)

func ParseIDP(r *http.Request) string {
	var idp string
	forms.MustParse(r, forms.Schema{"idp": forms.String(&idp)})
	return idp
}

func ParseCodeState(r *http.Request) (string, string, error) {
	var (
		code  string
		state string
		fail  string
	)

	if err := forms.Parse(r, forms.Schema{
		"code":  forms.String(&code),
		"state": forms.String(&state),
		"error": forms.StringOr(&fail, ""),
	}); err != nil {
		return "", "", err
	}

	if fail == "" {
		return code, state, nil
	}

	return "", "", errors.New(fail)
}

var nonceRe = regexp.MustCompile(`nonce=([a-f0-9-]{36})`)

func ParseNonce(state string) *conceal.Text {
	// should be in the form nonce=<uuid>; return empty string if not
	results := nonceRe.FindStringSubmatch(state)
	if len(results) != 2 {
		return conceal.New("")
	}
	return conceal.New(results[1])
}
