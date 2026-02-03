package microsoftkeys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"cattlecloud.net/go/scope"
	"cattlecloud.net/go/webtools/middles/oauth"

	"github.com/golang-jwt/jwt/v5"
)

// public is the official oauth certificate endpoint for microsoft
const public = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

type Claims struct {
	// JWT standard types (scope: oidc)
	jwt.RegisteredClaims

	// Microsoft custom types (scope: email)
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

func (v *validator) Validate(token string) (*Claims, error) {
	now := time.Now().UTC().Unix()

	claims := new(Claims)

	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(t *jwt.Token) (any, error) {
			keyID := fmt.Sprintf("%s", t.Header["kid"])
			cert64, err0 := v.getMicrosoftCert(keyID)
			if err0 != nil {
				return nil, err0
			}

			certBytes, err1 := base64.StdEncoding.DecodeString(cert64)
			if err1 != nil {
				return nil, err1
			}

			cert509, err2 := x509.ParseCertificate(certBytes)
			if err2 != nil {
				return nil, err2
			}

			certPub, ok := cert509.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("oauth/microsoftkeys: cannot convert x509 certificate")
			}

			return certPub, nil
		},
	)

	// unable to get token or parse it
	if err != nil {
		return nil, fmt.Errorf("oauth/microsoftkeys: unable to parse Microsoft JWT: %w", err)
	}

	claims2, ok := parsed.Claims.(*Claims)
	if !ok {
		return nil, errors.New("oauth/microsoftkeys: Microsoft JWT is malformed")
	}

	if !strings.HasPrefix(claims2.Issuer, "https://login.microsoftonline.com/") {
		return nil, errors.New("oauth/microsoftkeys: Microsoft JWT iss is not valid")
	}

	if !slices.Contains(claims.Audience, v.id) {
		return nil, errors.New("oauth/microsoftkeys: Microsoft JWT aud is not valid")
	}

	if claims2.ExpiresAt.Unix() < now {
		return nil, errors.New("oauth/microsoftkeys: Microsoft JWT is expired")
	}

	// there is no microsoft email validation option

	return claims2, nil
}

func (v *validator) getMicrosoftCert(keyID string) (string, error) {
	public, exists := v.vc.Get(keyID)

	switch {
	case exists:
		return public, nil
	default:
		// no such certificate in the cache;
		// continue with http request to microsoft for a certificate
	}

	ctx, cancel := scope.TTL(30 * time.Second)
	defer cancel()

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	response, err := v.hc.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	data := make(map[string]any)
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return "", err
	}

	keys, ok := data["keys"].([]any)
	if !ok {
		return "", errors.New("oauth/microsoftkeys: Microsoft keys in unexpected format")
	}

	var wanted string

	// iterate each key and put it into the cache
	for _, item := range keys {
		key := item.(map[string]any)
		id := key["kid"].(string)
		value := key["x5c"].([]any)[0].(string)
		v.vc.Put(id, value, 1*time.Hour)

		// hold onto the key we were looking for if we see it
		if id == keyID {
			wanted = value
		}
	}

	// did we find the key we were looking for?
	if wanted == "" {
		return "", errors.New("oauth/microsoftkeys: no Microsoft key found")
	}

	return wanted, nil
}
