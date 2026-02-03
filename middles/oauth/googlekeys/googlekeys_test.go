package googlekeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shoenig/test/must"
)

func TestValidator_Validate(t *testing.T) {
	t.Parallel()

	const kid = "test-key-id"
	const clientID = "test-case-client"

	// generate RSA keypair for testing
	privateKey, perr := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(t, perr)

	// encode public key into PEM format (as expected by validator)
	publicKey, berr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	must.NoError(t, berr)
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKey,
	})

	// create test server that returns our test case public key
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		data := map[string]string{
			kid: string(publicKeyPem),
		}
		jerr := json.NewEncoder(w).Encode(data)
		must.NoError(t, jerr)
	}))
	t.Cleanup(ts.Close)

	// initialize the validator pointing to test server
	v := New(
		SetHTTP(ts.Client()),
		SetClientID(clientID),
		SetEndpoint(ts.URL),
	)

	// create signed JWT satisfying the Google claims validator
	// i.e. should look like a real Google JWT
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://accounts.google.com",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   "1234567890",
		},
		Email:         "tester@example.com",
		EmailVerified: true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid // link the token to our key ID
	signedToken, err := token.SignedString(privateKey)
	must.NoError(t, err)

	// finally do the actual validation
	validation, verr := v.Validate(signedToken)
	must.NoError(t, verr)

	// ensure the token claims are as expected
	must.Eq(t, "tester@example.com", validation.Email)
	must.True(t, validation.EmailVerified)
}

func TestValidator_certsTTL(t *testing.T) {
	t.Parallel()

	t.Run("actual", func(t *testing.T) {
		v := new(validator)

		response := &http.Response{
			Header: map[string][]string{
				"Expires": {"Fri, 01 Nov 2024 00:34:53 GMT"},
			},
		}

		now := time.Date(2024, 10, 31, 13, 50, 10, 0, time.UTC)

		ttl := v.certsTTL(now, response)

		exp := 10*time.Hour + 44*time.Minute + 43*time.Second
		must.Eq(t, exp, ttl)
	})

	t.Run("parse-failure", func(t *testing.T) {
		v := new(validator)

		response := &http.Response{
			Header: map[string][]string{
				"Expires": {"Bob, 01 Nov 2024 00:34:53 GMT"},
			},
		}

		now := time.Date(2024, 10, 31, 13, 50, 10, 0, time.UTC)

		ttl := v.certsTTL(now, response)

		exp := 1 * time.Hour // the fallback cache expiration
		must.Eq(t, exp, ttl)
	})
}
