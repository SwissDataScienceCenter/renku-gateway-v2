package main

import (
	"fmt"
	"net/http"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/gwerrors"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/labstack/echo/v4"
)

const SessionIDCtxKey string = "sessionID"

func (l *LoginServer) GetLogin(c echo.Context, params GetLoginParams) error {
	var session models.Session
	var err error
	var appRedirectURL string
	var providerIDs models.SerializableStringSlice

	// Check redirect parameters
	if params.RedirectUrl != nil && *params.RedirectUrl != "" {
		appRedirectURL = *params.RedirectUrl
	} else {
		appRedirectURL = l.config.DefaultAppRedirectURL
	}
	// Check provider IDs requested for login
	if params.ProviderId != nil && len(*params.ProviderId) > 0 {
		providerIDs = *params.ProviderId
	} else {
		providerIDs = l.config.DefaultProviderIDs
	}
	// Get the session from the context - the session middleware already got it from the store
	session, ok := c.Get(commonconfig.SessionCtxKey).(models.Session)
	if !ok {
		return gwerrors.ErrSessionParse
	}
	session.SetProviderIDs(providerIDs)

	// Setup csrf
	csrf, err := providerstore.NewLoginCSRF(
		"",
		l.config.CSRFCookie,
	) // coder verifiers are in the session not in CSRF cookie
	if err != nil {
		return err
	}

	// Get all login urls and update them in session
	loginURLs, codeVerifiers, err := l.providerStore.LoginURLs(
		l.config.CallbackURL,
		appRedirectURL,
		csrf.HashOIDCNonce(),
		csrf.HashOAuthState(),
		session.LoginWithProviders...)
	if err != nil {
		return err
	}
	session.SetLoginURLs(loginURLs)
	session.SetCodeVerifiers(codeVerifiers)

	// Make csrf cookie
	if _, err := csrf.SetCookie(c.Response().Writer, c.Request()); err != nil {
		return err
	}

	return l.oAuthNext(c, session)
}

// oauthStart sets up the beginning of the oauth flow and ends with
// the redirect of the user to the Provider's login and authorization page.
// Adapted from oauth2-proxy code.
func (l *LoginServer) oAuthNext(
	c echo.Context,
	session models.Session,
) error {
	// Get the next url to redirect to
	loginURL := session.PopLoginURL()
	// Persist session in store
	err := l.sessionStore.SetSession(c.Request().Context(), session)
	if err != nil {
		return err
	}
	// If at the end of login flow clear CSRF cookie
	if len(session.LoginURLs) == 0 {
		c.SetCookie(&http.Cookie{Name: l.config.CSRFCookieName(), Value: "", MaxAge: -1})
	}
	// Redirect to the provider's login page (or the application if at the end of login sequence)
	return c.Redirect(http.StatusFound, loginURL)
}

func (l *LoginServer) GetCallback(c echo.Context) error {
	session, ok := c.Get(commonconfig.SessionCtxKey).(models.Session)
	if !ok {
		return fmt.Errorf("cannot cast session from context")
	}
	providerID := session.PopProviderID()
	provider, found := l.providerStore.Get(providerID)
	if !found {
		return fmt.Errorf("provider not found %s", providerID)
	}

	err := c.Request().ParseForm()
	if err != nil {
		c.Logger().Errorf("Error while parsing OAuth2 callback: %v", err)
		return c.String(http.StatusInternalServerError, err.Error())
	}
	errorString := c.Request().Form.Get("error")
	if errorString != "" {
		c.Logger().Errorf("Error while parsing OAuth2 callback: %s", errorString)
		return c.String(
			http.StatusForbidden,
			fmt.Sprintf("Login Failed: The upstream identity provider returned an error: %s", errorString),
		)
	}
	csrf, err := providerstore.LoadCSRFCookie(c.Request(), l.config.CSRFCookie)
	if err != nil {
		c.Logger().Printf("Invalid authentication via OAuth2: unable to obtain CSRF cookie\n")
		return c.String(
			http.StatusForbidden,
			fmt.Sprintf("Login Failed: Unable to find a valid CSRF token. Please try again"),
		)
	}

	// Get access and refresh tokens for oauth2-proxy response
	accessToken, refreshToken, err := provider.RedeemTokens(
		c.Request(),
		session.PopCodeVerifier(),
		l.config.CallbackURL,
		csrf,
	)
	if err != nil {
		return err
	}
	// Store access and refresh tokens in session and persist session
	session.AddTokenID(accessToken.ID)
	err = l.tokenStore.SetAccessToken(c.Request().Context(), accessToken)
	if err != nil {
		return err
	}
	err = l.tokenStore.SetRefreshToken(c.Request().Context(), refreshToken)
	if err != nil {
		return err
	}

	return l.oAuthNext(c, session)
}

// GetLogout logs the user out of the current session, removing the session cookie and removing the session
// in the session store.
func (l *LoginServer) GetLogout(c echo.Context, params GetLogoutParams) error {
	// figure out redirectURL
	var redirectURL = l.config.DefaultAppRedirectURL
	if params.RedirectUrl != nil {
		redirectURL = *params.RedirectUrl
	}
	// get session cookie
	cookie, err := c.Request().Cookie(commonconfig.SessionCookieName)
	if err == http.ErrNoCookie {
		return c.Redirect(http.StatusFound, redirectURL)
	}
	if err != nil {
		return err
	}
	// remove the session
	if cookie.Value != "" {
		if err := l.sessionStore.RemoveSession(c.Request().Context(), cookie.Value); err != nil {
			return err
		}
	}
	// remove the cookie
	c.SetCookie(&http.Cookie{Name: commonconfig.SessionCookieName, Value: "", MaxAge: -1})
	// redirect
	return c.Redirect(http.StatusFound, redirectURL)
}

func (*LoginServer) PostCliLoginComplete(c echo.Context) error {
	return c.String(http.StatusOK, "Coming soon")
}

func (*LoginServer) PostCliLoginInit(c echo.Context) error {
	return c.String(http.StatusOK, "Coming soon")
}

func (*LoginServer) GetHealth(c echo.Context) error {
	return c.String(http.StatusOK, "Running")
}
