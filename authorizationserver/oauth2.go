package authorizationserver

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"time"
)

var (
	config = &compose.Config{
		AccessTokenLifespan: time.Minute * 30,
	}

	store = storage.NewExampleStore()

	secret = []byte("some-cool-secret-that-is-32bytes")

	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

var oauth2 = compose.ComposeAllEnabled(config, store, secret, privateKey)

func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     user,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}
