package main

import (
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/commonmiddlewares"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type LoginServer struct {
	sessionStore  SessionStore
	providerStore ProviderStore
	tokenStore    TokenStore
	config        *LoginServerConfig
	echo          *echo.Echo
}

// defaultProviders generates a list of login providers from the providerstore based
// on the default providers specified in the configuration.
func (l *LoginServer) defaultProviders() ([]providerstore.Provider, bool) {
	output := []providerstore.Provider{}
	for _, id := range l.config.DefaultProviderIDs {
		provider, found := l.providerStore.Get(id)
		if !found {
			return []providerstore.Provider{}, false
		}
		output = append(output, provider)
	}
	return output, true
}

// SetProviderStore sets a specific provider store on the login server.
func (l *LoginServer) SetProviderStore(providerStore ProviderStore) {
	l.providerStore = providerStore
}

// NewLoginServer creates a new LoginServer that handles the callbacks from oauth2
// and initiates the login flow for users.
func NewLoginServer(config *LoginServerConfig) (*LoginServer, error) {
	store, err := config.PersistenceAdapter()
	if err != nil {
		return nil, err
	}
	providerStore, err := config.ProviderStore()
	if err != nil {
		return nil, err
	}
	server := &LoginServer{
		sessionStore:  store,
		tokenStore:    store,
		config:        config,
		providerStore: providerStore,
	}

	e := echo.New()
	e.Use(
		middleware.Recover(),
	)
	sessionMiddleware := commonmiddlewares.NewSessionMiddleware(
		store,
		commonconfig.SessionCookieName,
		!config.sessionCookieNotSecure,
	)
	commonMiddleware := []echo.MiddlewareFunc{
		middleware.Logger(),
		NoCaching,
		sessionMiddleware.Middleware(models.Default),
	}

	wrapper := ServerInterfaceWrapper{Handler: server}
	e.GET(config.Server.BaseURL+"/callback", wrapper.GetCallback, commonMiddleware...)
	e.POST(config.Server.BaseURL+"/cli/login-complete", wrapper.PostCliLoginComplete, commonMiddleware...)
	e.POST(config.Server.BaseURL+"/cli/login-init", wrapper.PostCliLoginInit, commonMiddleware...)
	e.GET(config.Server.BaseURL+"/health", wrapper.GetHealth)
	e.GET(config.Server.BaseURL+"/login", wrapper.GetLogin, commonMiddleware...)
	e.GET(config.Server.BaseURL+"/logout", wrapper.GetLogout, middleware.Logger(), NoCaching)
	server.echo = e

	return server, nil
}
