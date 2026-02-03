package applekeys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shoenig/test/must"
)

func TestValidator_Validate(t *testing.T) {
	t.Parallel()

	const kid = "test-apple-kid"
	const clientID = "test-apple-client"

	// generate RSA keypair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(t, err)

	// prepare the public key components (n and e) in Base64 RawURL format
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())

	// exponent is usually 65537 (AQAB in base64)
	eb := big.NewInt(int64(privateKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eb)

	// create test server that mimics Apple's JWKS endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"keys": []map[string]string{
				{
					"kid": kid,
					"kty": "RSA",
					"n":   n,
					"e":   e,
				},
			},
		}
		jerr := json.NewEncoder(w).Encode(resp)
		must.NoError(t, jerr)
	}))
	t.Cleanup(ts.Close)

	// initialize the validator pointing to the test server
	v := New(
		SetHTTP(ts.Client()),
		SetClientID(clientID),
		SetEndpoint(ts.URL),
	)

	// create signed JWT satisfying the Apple claims validator
	// i.e. should look like a real Apple JWT
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://appleid.apple.com",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   "apple-user-123",
		},
		Email:         "apple-tester@example.com",
		EmailVerified: true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(privateKey)
	must.NoError(t, err)

	// finally do the actual validation
	validatedClaims, err := v.Validate(signedToken)

	// ensure the token claims are as expected
	must.NoError(t, err)
	must.Eq(t, "apple-tester@example.com", validatedClaims.Email)
	must.True(t, validatedClaims.EmailVerified)
	must.Eq(t, "apple-user-123", validatedClaims.Subject)
}
