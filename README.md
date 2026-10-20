# webtools

[![Go Reference](https://pkg.go.dev/badge/cattlecloud.net/go/webtools.svg)](https://pkg.go.dev/cattlecloud.net/go/webtools)
[![License](https://img.shields.io/github/license/cattlecloud/webtools?color=7C00D8&style=flat-square&label=License)](https://github.com/cattlecloud/webtools/blob/main/LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/cattlecloud/webtools/ci.yaml?style=flat-square&color=0FAA07&label=Tests)](https://github.com/cattlecloud/webtools/actions/workflows/ci.yaml)

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

##### sanitize a url

Use `Sanitize` to remove known trackers from URL parameters.

```go
u := webtools.Sanitize("https://example.org?utm_source=abc123&page=1")
// utm_source=abc123 is removed from the url
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

There is also the `Origins` convenience function for parsing the user-agent
of an `http.Request` and creating a struct of interesting values regarding the
request.

```go
ua := webtools.Origins(r)

fmt.Println(ua.String()) # e.g. curl/unknown
fmt.Println(ua.Anchor()) # e.g. example.org/path/to/page
fmt.Println(ua.From())   # e.g. 10.0.0.1
```

##### Origin headers

The `From()` method returns the originating client IP. The address is
parsed from HTTP headers at construction time (`Origins()`) using the
following precedence:

1. `Forwarded` (RFC 7239) — the leftmost usable `for=` parameter. Surrounding
   double-quotes are stripped, and any port is stripped. Redacted tokens
   (`unknown`, `_hidden`, and any value beginning with `_`) are treated as
   missing and cause a fall-through.
2. `X-Forwarded-For` — the leftmost comma-separated entry with any port
   stripped.
3. `X-Real-IP` — common nginx convention, with any port stripped.
4. `RemoteAddr` — the host portion of the TCP source address, via
   `net.SplitHostPort`.

Regardless of which source produced the value:

- Ports are always stripped (IPv4 `:port`, bracketed IPv6 `[::1]:port`,
  bare hostnames `:port`).
- The leftmost entry is always returned. Each proxy along the chain appends
  to the right, so the leftmost value is the one nearest the originating
  client.
- Redacted `Forwarded` tokens (`for=unknown`, `for=_hidden`) are silently
  dropped so callers transparently fall back to the next source rather
  than logging an opaque placeholder.

In all three header layouts below `From()` returns the same value for the
same originating client:

```go
// 1. RFC 7239 Forwarded header
r.Header.Set("Forwarded", "for=192.0.2.43;proto=https")
// From() -> 192.0.2.43

// 2. Legacy X-Forwarded-For (most common in practice)
r.Header.Set("X-Forwarded-For", "192.0.2.43, 10.0.0.5, proxy.example.com")
// From() -> 192.0.2.43   (leftmost = originating client)

// 3. nginx-style X-Real-IP, or nothing at all
r.Header.Set("X-Real-IP", "192.0.2.43")
// From() -> 192.0.2.43
```

#### package webtools/htmx

Provides utilities for building HTMX-compatible responses. The package includes an `Interface` for rendering HTMX responses, along with support for plain text, raw HTML, and templated content.

##### Response interfaces

```go
type Interface interface {
    Write(io.Writer) error
}
```

##### Rendering responses

```go
htmx.Write(
		w, // any io.Writer; typically http.ResponseWriter
    htmx.Text{Content: "Hello, World!"},
)
```

##### Using templates

```go
//go:embed templates/*
var templates embed.FS

tmplFS := htmx.FS(templates, "templates")

http.HandleFunc("GET /partial", func(w http.ResponseWriter, r *http.Request) {
    htmx.Write(w, &htmx.Template{
        FS:       tmplFS,
        Filename: "button.html",
        Fields:   data,
    })
})
```

##### Inline templates with Component

Use `Component` for rendering raw HTML templates defined inline:

```go
html := `<button hx-post="/click">{{ .Count }} clicks</button>`

htmx.Write(w, &htmx.Component{
    HTML:   html,
    Fields: struct{ Count int }{Count: 42},
})
```

##### Client-side redirects

Use `SetRedirect` instead of `http.Redirect` when handling HTMX requests to perform a client-side redirect:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    htmx.SetRedirect(w, "/new-page")
}
```

##### Preventing swap

Use `SetNoSwap` to keep existing content in place after a HTMX transition. Useful for setting error messages on forms:

```go
func errorHandler(w http.ResponseWriter, err error) {
    htmx.SetNoSwap(w)
    htmx.Write(w, htmx.Text{Content: err.Error()})
}
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

#### package webtools/httpclient

Provides a sharable `http.Client` that sets sensible values for maintaining a
pool of idle connections.

```go
client := httpclient.Get()
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
