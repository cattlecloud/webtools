package identity

import "github.com/shoenig/go-conceal"

type UserIdentity any

// UserData is the data stored in a session cookie.
type UserData[I UserIdentity] interface {
	Identity() I
	Token() *conceal.Text
}

// UserSession is a live session, established by a middleware after validating
// the session cookie and its associated server-side token.
type UserSession[I UserIdentity] interface {
	Identity() I
	Token() *conceal.Text
	Active() bool
}
