package identity

import "github.com/shoenig/go-conceal"

type UserIdentity any

type UserData[I UserIdentity] interface {
	Identity() I
	Token() *conceal.Text
}

type UserSession[I UserIdentity] interface {
	Identity() I
	Active() bool
}
