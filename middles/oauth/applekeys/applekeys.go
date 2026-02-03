package applekeys

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"time"

	"cattlecloud.net/go/scope"
	"cattlecloud.net/go/webtools/middles/oauth"
	"github.com/golang-jwt/jwt/v5"
)

// public is the official oauth certificate endpoint for apple
const public = "https://appleid.apple.com/auth/keys"

type Claims struct {
	// JWT standard types (scope: oidc)
	jwt.RegisteredClaims

	// Apple Custom Types (scope: email)
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type Options struct {
	endpoint   string
	cache      oauth.Cache[string, *rsa.PublicKey]
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
		cache:      oauth.NewVolatileCache[*rsa.PublicKey](8),
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
	vc  oauth.Cache[string, *rsa.PublicKey]
	hc  *http.Client
	id  string
	url string
}

func (v *validator) Validate(token string) (*Claims, error) {
	claims := new(Claims)

	// parse the token into claims object
	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(t *jwt.Token) (any, error) {
			keyID := fmt.Sprintf("%s", t.Header["kid"])
			return v.getAppleCert(keyID)
		},
	)

	// unable to get token or parse it
	if err != nil {
		return nil, fmt.Errorf("oauth/applekeys: unable to parse Apple JWT: %w", err)
	}

	if !parsed.Valid {
		return nil, errors.New("oauth/applekeys: Apple JWT not valid")
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, errors.New("oauth/applekeys: Apple JWT issuer not valid")
	}

	if !slices.Contains(claims.Audience, v.id) {
		return nil, errors.New("oauth/applekeys: Apple JWT audience not valid")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("oauth/applekeys: Apple JWT is expired")
	}

	if !claims.EmailVerified {
		return nil, errors.New("oauth/applekeys: Apple email is not verified")
	}

	return claims, nil
}

func (v *validator) getAppleCert(keyID string) (*rsa.PublicKey, error) {
	public, exists := v.vc.Get(keyID)

	switch {
	case exists:
		return public, nil
	default:
		// no such certificate in the cache;
		// continue with http request to apple for a certificate
	}

	ctx, cancel := scope.TTL(30 * time.Second)
	defer cancel()

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	response, derr := v.hc.Do(request)
	if derr != nil {
		return nil, derr
	}
	defer func() { _ = response.Body.Close() }()

	var data struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, err
	}

	for _, key := range data.Keys {
		if key.Kid == keyID {
			nBytes, err1 := base64.RawURLEncoding.DecodeString(key.N)
			if err1 != nil {
				return nil, err1
			}
			eBytes, err2 := base64.RawURLEncoding.DecodeString(key.E)
			if err2 != nil {
				return nil, err2
			}
			n := new(big.Int).SetBytes(nBytes)
			e := int(new(big.Int).SetBytes(eBytes).Int64())
			public := &rsa.PublicKey{N: n, E: e}

			// set the key we got into the cache
			v.vc.Put(keyID, public, 1*time.Hour)

			return public, nil
		}
	}

	return nil, errors.New("oauth/applekeys: Apple public key not found")
}
