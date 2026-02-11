package middles

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"cattlecloud.net/go/webtools/middles/identity"
	"github.com/shoenig/go-conceal"
)

type Sessions[I identity.UserIdentity] interface {
	Create(I, time.Duration) *http.Cookie
	Match(I, *conceal.Text) error
}

// GetSession extracts the user session out of the http.Request, which will
// be an implementation of identity.UserSession.
//
// If on session is found, an implementation of identity.UserSession where
// .Active() always returns false is returned, indicating there is no session.
func GetSession[I identity.UserIdentity](r *http.Request) identity.UserSession[I] {
	value, ok := r.Context().Value(sessionContextKey).(identity.UserSession[I])
	if !ok {
		return &session[I]{
			active: false,
		}
	}
	return value
}

type userSessionKey struct{}

var sessionContextKey = userSessionKey{}

type SetSession[D identity.UserData[I], I identity.UserIdentity] struct {
	SessionCookieName string
	Sessions          Sessions[I]
	Next              http.Handler
}

func (ss *SetSession[D, I]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	abort := func() {
		// explicitly set inactive; ensuring no operation requiring a session works
		none := &session[I]{active: false}
		ctx2 := context.WithValue(r.Context(), sessionContextKey, none)
		r2 := r.WithContext(ctx2)
		ss.Next.ServeHTTP(w, r2)
	}

	// try to get a cookie from the request
	cookie, cerr := r.Cookie(ss.SessionCookieName)

	// if no cookie, force no session on the context
	if cerr != nil {
		abort()
		return
	}

	// there is a cookie, now we must verify the cookie is legit
	var data D
	bs := fromBase64(cookie.Value)
	if jerr := json.Unmarshal([]byte(bs), &data); jerr != nil {
		abort()
		return
	}

	// lookup the associated session token from cache
	merr := ss.Sessions.Match(data.Identity(), data.Token())
	if merr != nil {
		// probably malicious; assume no session
		abort()
		return
	}

	// we found a matching token; we can allow the session
	live := &session[I]{id: data.Identity(), active: true}
	ctx2 := context.WithValue(r.Context(), sessionContextKey, live)
	r2 := r.WithContext(ctx2)

	ss.Next.ServeHTTP(w, r2)
}

// session is a minimal implementation of identity.UserSession; useful for
// allowing an identity based session to be recognized as active or not.
type session[I identity.UserIdentity] struct {
	id     I
	active bool
}

func (s *session[I]) Identity() I {
	return s.id
}

func (s *session[I]) Active() bool {
	return s.active
}

func fromBase64(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}
