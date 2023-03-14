package main

import (
	"net/url"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/gwerrors"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/labstack/echo/v4"
)

type tokenStore interface {
	models.AccessTokenGetter
	models.RefreshTokenGetter
}

// CredsInjectionMiddleware is used to inject the credentials required by any upstream (renku component)
// service that the proxy is load balancing or routing for.
type CredsInjectionMiddleware struct {
	tokenStore          tokenStore
	loginURL            *url.URL
	injectRefreshTokens bool
	allowAnonymous      bool
}

// GetMiddleware generates the echo middleware that injects the credentials.
func (m *CredsInjectionMiddleware) Middleware(
	injector func(
		c echo.Context, accessTokens map[string]models.OauthToken, refreshTokens map[string]models.OauthToken,
	) error,
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			session, ok := c.Get(commonconfig.SessionCtxKey).(models.Session)
			if !ok {
				return gwerrors.ErrSessionParse
			}
			if len(session.TokenIDs) == 0 && m.allowAnonymous {
				return next(c)
			}
			accessTokens, err := m.tokenStore.GetAccessTokens(c.Request().Context(), session.TokenIDs...)
			if err != nil {
				return err
			}
			refreshTokens := map[string]models.OauthToken{}
			if m.injectRefreshTokens {
				refreshTokens, err = m.tokenStore.GetRefreshTokens(c.Request().Context(), session.TokenIDs...)
				if err != nil {
					return err
				}
			}
			err = injector(c, accessTokens, refreshTokens)
			if err != nil {
				return err
			}
			// The user is fully logged in, all required credentials required by upstream services have been injected
			return next(c)
		}
	}
}
