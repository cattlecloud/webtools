package oauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/shoenig/go-conceal"
	"github.com/shoenig/test/must"
)

func testNow() time.Time {
	return time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
}

const testUser = 12345

type rowid uint // example of Unique type

func TestCookieFactory_Create_NameAndPath(t *testing.T) {
	t.Parallel()

	cf := &CookieFactory[rowid]{
		Name:  "session-id",
		Clock: testNow,
	}

	token := conceal.New("secret-token")
	cookie := cf.Create(testUser, token, 1*time.Hour)
	must.Eq(t, "session-id", cookie.Name)
	must.Eq(t, "/", cookie.Path)
	must.True(t, cookie.HttpOnly)
}

func TestCookieFactory_Create_Expiration(t *testing.T) {
	t.Parallel()

	cf := &CookieFactory[rowid]{
		Clock: testNow,
	}

	ttl := 2 * time.Hour
	expectedExpiry := testNow().Add(ttl)
	token := conceal.New("secret-token")
	cookie := cf.Create(testUser, token, ttl)
	must.Eq(t, expectedExpiry, cookie.Expires)
}

func TestCookieFactory_Create_SecureFlag(t *testing.T) {
	t.Parallel()

	cf := &CookieFactory[rowid]{
		Clock:  testNow,
		Secure: true,
	}

	token := conceal.New("secret-token")
	cookie := cf.Create(testUser, token, 1*time.Hour)
	must.True(t, cookie.Secure)
}

func TestCookieFactory_Create_ValueEncoding(t *testing.T) {
	t.Parallel()

	cf := &CookieFactory[rowid]{
		Clock: testNow,
	}

	rawToken := "super-secret-session-string"
	token := conceal.New(rawToken)
	cookie := cf.Create(testUser, token, 1*time.Hour)
	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	must.NoError(t, err)

	var content CookieContent[rowid]
	jerr := json.Unmarshal(decoded, &content)
	must.NoError(t, jerr)

	must.Eq(t, rawToken, content.UserToken)
	must.Eq(t, testUser, content.UserID)
}
