package main

import (
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
)

type TokenStore interface {
	models.AccessTokenGetter
	models.AccessTokenSetter
	models.AccessTokenRemover
	models.RefreshTokenGetter
	models.RefreshTokenSetter
	models.RefreshTokenRemover
}

type SessionStore interface {
	models.SessionGetter
	models.SessionSetter
	models.SessionRemover
}

type SessionTokenStore interface {
	SessionStore
	TokenStore
}

type ProviderStore interface {
	Get(id string) (providerstore.Provider, bool)
	LoginURLs(
		callbackURL string,
		finalRedirectURL string,
		oidcNonceHash string,
		state string,
		ids ...string,
	) (loginURLs []string, codeVerifiers []string, err error)
}
