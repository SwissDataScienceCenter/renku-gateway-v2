package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
)

// notebooksKcInjector injects the appropriate headers from a set of access and refresh tokens from Keycloak that
// are required by the notebook service.
func notebooksKcInjector(c echo.Context, accessTokens, refreshTokens map[string]models.OauthToken) error {
	accessToken, found := accessTokens[renkuAuthProviderID]
	if !found {
		return nil
	}
	refreshToken, found := refreshTokens[renkuAuthProviderID]
	if !found {
		return nil
	}
	c.Request().Header.Set("Renku-Auth-Access-Token", accessToken.Value)
	// The notebook service uses the claims from the ID token that are already available in the access token
	c.Request().Header.Set("Renku-Auth-Id-Token", accessToken.Value)
	c.Request().Header.Set("Renku-Auth-Refresh-Token", refreshToken.Value)
	return nil
}

// notebooksGitlabInjector injects the gitlab access token in the Authorization header as bearer token
func notebooksGitlabInjector(c echo.Context, accessTokens, _ map[string]models.OauthToken) error {
	gitlabToken, found := accessTokens[gitlabAuthProviderID]
	if !found {
		return nil
	}
	type gitlabCreds struct {
		Provider             string `json:"provider"`
		AuthorizationHeader  string `json:"AuthorizationHeader"`
		AccessTokenExpiresAt int64  `json:"AccessTokenExpiresAt"`
	}
	gitURL, err := url.Parse(gitlabToken.TokenURL)
	if err != nil {
		return err
	}
	if strings.HasPrefix(gitURL.RequestURI(), "/gitlab") {
		gitURL.Path = "/gitlab"
		gitURL.RawPath = "/gitlab"
	} else {
		gitURL.Path = ""
		gitURL.RawPath = ""
	}
	gitURL.RawFragment = ""
	gitURL.RawQuery = ""
	creds := map[string]gitlabCreds{
		gitURL.String(): {
			Provider:             gitlabToken.ProviderID,
			AuthorizationHeader:  fmt.Sprintf("bearer %s", gitlabToken.Value),
			AccessTokenExpiresAt: gitlabToken.ExpiresAt.Unix(),
		},
	}
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	c.Request().Header.Set("Renku-Auth-Git-Credentials", base64.StdEncoding.EncodeToString(credsJSON))
	return nil
}

// gitlabInjector injects the gitlab access token in the Authorization header as bearer token
func gitlabInjector(c echo.Context, accessTokens, _ map[string]models.OauthToken) error {
	gitlabToken, found := accessTokens[gitlabAuthProviderID]
	if !found {
		return nil
	}
	c.Request().Header.Set(http.CanonicalHeaderKey("authorization"), fmt.Sprintf("Bearer %s", gitlabToken.Value))
	return nil
}

// uiServerGitlabInjector injects gitlab access token in a specific header used by the ui server.
func uiServerGitlabInjector(c echo.Context, accessTokens, _ map[string]models.OauthToken) error {
	gitlabToken, found := accessTokens[gitlabAuthProviderID]
	if !found {
		return nil
	}
	c.Request().Header.Set(
		http.CanonicalHeaderKey("Renku-Gateway-Upstream-Authorization"),
		fmt.Sprintf("bearer %s", gitlabToken.Value),
	)
	return nil
}

// coreKcInjector injects specific claims from the Keycloak access token into the request for the core service.
func coreKcInjector(c echo.Context, accessTokens, _ map[string]models.OauthToken) error {
	accessToken, found := accessTokens[renkuAuthProviderID]
	if !found {
		return nil
	}
	claims := jwt.MapClaims{}
	// The token is trusted because it comes directly from our redis store where tokens are verified when added.
	_, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(accessToken.Value, &claims)
	if err != nil {
		return err
	}
	claimsToInject := map[string]string{
		// the key is the name of the claim, the value is the header key where the claim will be injected
		"sub":   "Renku-user-id",
		"name":  "Renku-user-fullname",
		"email": "Renku-user-email",
	}
	for claimName, headerName := range claimsToInject {
		claimValueRaw, found := claims[claimName]
		if !found {
			return fmt.Errorf("cannot find the %s claim in the Keycloak access token for the CLI", claimName)
		}
		claimValue, ok := claimValueRaw.(string)
		if !ok {
			return fmt.Errorf("cannot convert the %s claim in the Keycloak access token to string", claimName)
		}
		c.Request().Header.Set(headerName, claimValue)
	}
	return nil
}
