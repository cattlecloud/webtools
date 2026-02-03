package microsoftkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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

	const kid = "test-microsoft-kid"
	const clientID = "test-ms-client"

	// generate RSA keypair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(t, err)

	// create a self-signed X.509 certificate
	// microsoft validator expects to parse a certificate from the x5c field.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Microsoft Auth"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		PublicKey: &privateKey.PublicKey,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	must.NoError(t, err)

	// encode to standard base64 as found in Microsoft's x5c fields
	certBase64 := base64.StdEncoding.EncodeToString(certBytes)

	// create test server that returns our test case public key
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"keys": []map[string]any{
				{
					"kid": kid,
					"kty": "RSA",
					"use": "sig",
					"x5c": []string{certBase64},
				},
			},
		}
		jerr := json.NewEncoder(w).Encode(resp)
		must.NoError(t, jerr)
	}))
	t.Cleanup(ts.Close)

	// initialize validator pointing to test server
	v := New(
		SetHTTP(ts.Client()),
		SetClientID(clientID),
		SetEndpoint(ts.URL),
	)

	// create signed JWT satisfying the Microsoft claims validator
	// i.e. should look like a real Microsoft JWT
	now := time.Now().UTC()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://login.microsoftonline.com/common/v2.0",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   "ms-user-789",
		},
		Email: "ms-tester@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid // link the token to our key ID
	signedToken, err := token.SignedString(privateKey)
	must.NoError(t, err)

	// finally do the actual validation
	validatedClaims, verr := v.Validate(signedToken)
	must.NoError(t, verr)

	// ensure the token claims are as expected
	must.Eq(t, "ms-tester@example.com", validatedClaims.Email)
	must.Eq(t, "ms-user-789", validatedClaims.Subject)
}
