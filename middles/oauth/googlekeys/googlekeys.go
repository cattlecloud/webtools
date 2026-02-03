package googlekeys

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"cattlecloud.net/go/scope"
	"cattlecloud.net/go/webtools/middles/oauth"
	"github.com/golang-jwt/jwt/v5"
)

// public is the official oauth certificate endpoint for google
const public = "https://www.googleapis.com/oauth2/v1/certs"

type Claims struct {
	// JWT standard types (scope: oidc)
	jwt.RegisteredClaims

	// Google custom types (scope: email)
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type Options struct {
	endpoint   string
	cache      oauth.Cache[string, string]
	httpClient *http.Client
	clientID   string
}

type OptionFunc func(*Options)

func SetHTTP(client *http.Client) OptionFunc {
	return func(o *Options) { o.httpClient = client }
}

func SetClientID(id string) OptionFunc {
	return func(o *Options) { o.clientID = id }
}

func SetEndpoint(s string) OptionFunc {
	return func(o *Options) { o.endpoint = s }
}

func New(opts ...OptionFunc) Validator {
	options := &Options{
		endpoint:   public,
		cache:      oauth.NewVolatileCache[string](8),
		httpClient: &http.Client{Timeout: 1 * time.Minute},
	}

	for _, opt := range opts {
		opt(options)
	}

	return &validator{
		vc:  options.cache,
		hc:  options.httpClient,
		id:  options.clientID,
		url: options.endpoint,
	}
}

type Validator interface {
	Validate(string) (*Claims, error)
}

type validator struct {
	vc  oauth.Cache[string, string]
	hc  *http.Client
	id  string
	url string
}

func (g *validator) Validate(token string) (*Claims, error) {
	now := time.Now().UTC().Unix()

	claims := new(Claims)

	// parse the token into claims object
	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(t *jwt.Token) (any, error) {
			keyID := fmt.Sprintf("%s", t.Header["kid"])
			pem, err := g.getGoogleCert(keyID)
			if err != nil {
				return nil, err
			}
			return jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
		},
	)

	// unable to get token or parse it
	if err != nil {
		return nil, fmt.Errorf("oauth/googlekeys: unable to parse Google JWT: %w", err)
	}

	claims2, ok := parsed.Claims.(*Claims)
	if !ok {
		return nil, errors.New("oauth/googlekeys: Google JWT is malformed")
	}

	if claims2.Issuer != "accounts.google.com" && claims2.Issuer != "https://accounts.google.com" {
		return nil, errors.New("oauth/googlekeys: Google JWT iss is not valid")
	}

	if !slices.Contains(claims.Audience, g.id) {
		return nil, errors.New("oauth/googlekeys: Google JWT aud is not valid")
	}

	if claims2.ExpiresAt.Unix() < now {
		return nil, errors.New("oauth/googlekeys: Google JWT is expired")
	}

	if !claims2.EmailVerified {
		return nil, errors.New("oauth/googlekeys: Google email is not verified")
	}

	return claims2, nil
}

func (g *validator) getGoogleCert(keyID string) (string, error) {
	public, exists := g.vc.Get(keyID)

	switch {
	case exists:
		return public, nil
	default:
		// no such certificate in the cache;
		// continue with http request to google for a certificate
	}

	ctx, cancel := scope.TTL(30 * time.Second)
	defer cancel()

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, g.url, nil)
	response, derr := g.hc.Do(request)
	if derr != nil {
		return "", derr
	}
	defer func() { _ = response.Body.Close() }()

	// extract the certificates Expires header to get cache TTL
	ttl := g.certsTTL(time.Now(), response)

	// extract the content of the response
	data := make(map[string]string)
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return "", err
	}

	// iterate each returned key and put it into the cache
	for k, v := range data {
		g.vc.Put(k, v, ttl)
	}

	// lookup the key we actually wanted
	key, exists := data[keyID]
	if !exists {
		return "", errors.New("oauth/googlekeys: Google public key not found")
	}

	return key, nil
}

func (g *validator) certsTTL(now time.Time, r *http.Response) time.Duration {
	header := r.Header.Get("Expires")

	expiration, err := time.Parse("Mon, 02 Jan 2006 15:04:05 MST", header)
	if err != nil {
		return 1 * time.Hour
	}

	return expiration.Sub(now)
}
