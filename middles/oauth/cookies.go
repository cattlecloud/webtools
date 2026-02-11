package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/shoenig/go-conceal"
)

// CookieFactory is used to bake cookies representing a user identity and
// associated unique session token.
//
// Each cookie minted is of the same name; i.e. the name associated with the
// cookie in the requester's cookie jar (web browser / http client).
type CookieFactory[U Unique] struct {
	Name   string
	Secure bool
	Clock  func() time.Time
}

// CookieContent is the data stored per session.
type CookieContent[U Unique] struct {
	UserToken string `json:"token"`
	UserID    U      `json:"user_id"`
}

// Token returns the secret token associated with the cookie.
func (cc *CookieContent[U]) Token() *conceal.Text {
	return conceal.New(cc.UserToken)
}

// Identity returns the identity associated with the cookie.
func (cc *CookieContent[U]) Identity() U {
	return cc.UserID
}

// Create the cookie.
func (cf *CookieFactory[U]) Create(
	id U,
	token *conceal.Text,
	ttl time.Duration,
) *http.Cookie {
	// compute the future time cookie expires
	expiration := cf.Clock().Add(ttl)

	// encode the cookie payload as base64 json
	b, _ := json.Marshal(&CookieContent[U]{
		UserToken: token.Unveil(),
		UserID:    id,
	})
	encoded := base64.StdEncoding.EncodeToString(b)

	// create and return our delicious cookie
	return &http.Cookie{
		Name:     cf.Name,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiration,
		SameSite: http.SameSiteLaxMode,
		Secure:   cf.Secure,
	}
}
