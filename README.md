# webtools

Package webtools is a collection of helper functions, types, and abstractions
for building standalone websites. In particular, sites that make use of oauth
based sessions for user identity and authentication.

### Getting Started

The `webtools` packages can be added to a Go project with `go get`.

```shell
go get cattlecloud.net/go/webtools@latest
```

```go
import "cattlecloud.net/go/webtools"
```

### Package Contents

#### package webtools

For setting common headers with correct values on `http.ResponseWriter` objects,
including:

- `Content-Type`

```go
webtools.SetContentType(w, webtools.ContentTypeRSS)
```

- `X-Robots-Tag`

```go
webtools.SetRobotsTag(w, webtools.RobotsYesIndex)
```

- `Cache-Control`

```go
webtools.SetCacheControl(w, 24 * time.Hour)
```

- `Authorization`

```go
webtools.SetBasicAuth(w, "admin", "passw0rd")
```

Also helps with crafting `net/url.URL` values with correctly encoded URL
paramter values.

##### creating a url

```go
u := webtools.CreateURL("example.org", "/some/path", map[string]string {
  "token": "abc123",
  "page":  "2",
})
```

#### package webtools/middles

Provides a generic sessions `http.Handler` which can be used to set and validate
user sessions. The primary interface is (optionally) implemented by using the
`oauth` and `identity` packages in this module.

```go
type Sessions[I identity.UserIdentity] interface {
	Create(I, time.Duration) *http.Cookie
	Match(I, *conceal.Text) error
}
```

#### package webtools/middles/identity

Provides a set of generic structs used for marshaling identity. The interfaces
are (optionally) implemented by using the `oauth` and `identity` packages in
this module.

```go
type UserIdentity any

type UserData[I UserIdentity] interface {
	Identity() I
	Token() *conceal.Text
}

type UserSession[I UserIdentity] interface {
	Identity() I
	Active() bool
}
```

#### package webtools/middles/oauth

Provides implementations for cookie creation, session management, and TTL
enabled session token caching. Intended to be used as the implementation details
of the `middles` and `identity` packages, and by using the `nonces`, `applekeys`,
`googlekeys`, and `microsoftkeys` packages as OAuth provider token validators.

##### 

#### package webtools/middles/oauth/nonces

Provides an implementation to manage `nonce` values used during the OAuth token
exchange. The primary interface enables you to `Create` a nonce, and then
`Consume` the nonce exactly once. 

```go
type Mint interface {
	Create() *conceal.Text
	Consume(*conceal.Text) error
}
```

#### package webtools/middles/oauth/applekeys

Provides an interface and implementation for validation JWT token claims as
issued by Apple.

```go
type Validator interface {
	Validate(string) (*Claims, error)
}
```

#### package webtools/middles/oauth/googlekeys

Provides an interface and implementation for validation JWT token claims as
issued by Google.

```go
type Validator interface {
	Validate(string) (*Claims, error)
}
```
#### package webtools/middles/oauth/microsoftkeys

Provides an interface and implementation for validation JWT token claims as
issued by Microsoft.

```go
type Validator interface {
	Validate(string) (*Claims, error)
}
```

### Notes on OAuth

The implementation details of what belongs in your `http.Handler` are currently
not a part of this suite of packages.

Firstly, you'll need to enable CSRF protection, which the Go standard library
has good support for as of Go 1.25; e.g.

```go
csrf := http.NewCrossOriginProtection()
_ = csrf.AddTrustedOrigin("https://appleid.apple.com")

// ...

server := &http.Server{
	Addr:    address,
	Handler: csrf.Handler(router),
}
```

For getting users logged in via their oauth provider, you'll need to have
handler(s) that go through the oauth handshake.

### License

The `cattlecloud.net/go/webtools` module is opensource under the [BSD-3-Clause](LICENSE) license.
