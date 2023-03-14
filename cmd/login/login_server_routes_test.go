package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestProviderConfig(authServers ...testAuthServer) (string, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	f, err := ioutil.TempFile("", id.String())
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, server := range authServers {
		_, err := f.Write([]byte(server.ProviderConfig() + "\n"))
		if err != nil {
			return "", err
		}
	}

	return f.Name(), nil
}

func getTestConfig(providersConfigFile string, defaultProviderIDs []string) (LoginServerConfig, error) {
	config := LoginServerConfig{
		DefaultProviderIDs: defaultProviderIDs,
		CSRFCookie: providerstore.CSRFCookieConfig{
			NamePrefix: "_gw",
			Secret:     "559df5ac2abac40d3013745db968b164",
			TTLMinutes: 5,
		},
		Server: ServerConfig{
			BaseURL: "/api/auth",
		},
		SessionPersistence: SessionPersistenceConfig{
			Type: "redis-mock",
		},
		TokenEncryption: TokenEncryptionConfig{
			Enabled:   true,
			SecretKey: "1b195c6329ba7df1c1adf6975c71910d",
		},
		ProviderConfigFile:     providersConfigFile,
		sessionCookieNotSecure: true,
	}
	return config, nil
}

func startTestServer(loginServer *LoginServer) (*httptest.Server, error) {
	server := httptest.NewServer(loginServer.echo)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		return nil, err
	}
	loginServer.config.DefaultAppRedirectURL = fmt.Sprintf("http://localhost:%d/api/auth/health", port)
	loginServer.config.CallbackURL = fmt.Sprintf("http://localhost:%d/api/auth/callback", port)
	loginServer.config.CSRFCookie.Path = fmt.Sprintf("http://localhost:%d", port)
	loginServer.config.Server.Port = port
	return server, nil
}

func TestGetLogin(t *testing.T) {
	var err error
	kcAuthServer := testAuthServer{
		Authorized:   true,
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		ClientID:     "renku",
	}
	kcAuthServer.Start()
	defer kcAuthServer.Server().Close()
	providers, err := getTestProviderConfig(kcAuthServer)
	require.NoError(t, err)
	defer os.Remove(providers)
	config, err := getTestConfig(providers, []string{"renku"})
	require.NoError(t, err)

	api, err := NewLoginServer(&config)
	require.NoError(t, err)
	apiServer, err := startTestServer(api)
	require.NoError(t, err)
	defer apiServer.Close()
	client := *http.DefaultClient
	jar, err := cookiejar.New(&cookiejar.Options{})
	require.NoError(t, err)
	client.Jar = jar

	testServerURL, err := url.Parse(strings.TrimRight(
		fmt.Sprintf("http://localhost:%d%s", config.Server.Port, config.Server.BaseURL),
		"/",
	))
	require.NoError(t, err)
	assert.Len(t, client.Jar.Cookies(testServerURL), 0)

	req, err := http.NewRequest(http.MethodGet, testServerURL.JoinPath("/login").String(), nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Len(t, client.Jar.Cookies(testServerURL), 1)

	sessionCookie := client.Jar.Cookies(testServerURL)[0]
	assert.Equal(t, commonconfig.SessionCookieName, sessionCookie.Name)
	session, err := api.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	require.NoError(t, err)
	assert.Len(t, session.TokenIDs, 1)
	assert.Len(t, session.LoginWithProviders, 0)
	assert.Len(t, session.LoginURLs, 0)
	assert.Len(t, session.CodeVerifiers, 0)
	assert.Equal(t, res.Request.URL.String(), config.DefaultAppRedirectURL)

	req, err = http.NewRequest(http.MethodGet, testServerURL.JoinPath("/logout").String(), nil)
	require.NoError(t, err)
	res, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	session, err = api.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, models.Session{}, session)
}

func TestGetLogin2Steps(t *testing.T) {
	var err error
	kcAuthServer1 := testAuthServer{
		Authorized:   true,
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		ClientID:     "renku1",
	}
	kcAuthServer1.Start()
	defer kcAuthServer1.Server().Close()
	kcAuthServer2 := testAuthServer{
		Authorized:   true,
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		ClientID:     "renku2",
	}
	kcAuthServer2.Start()
	defer kcAuthServer2.Server().Close()
	providers, err := getTestProviderConfig(kcAuthServer1, kcAuthServer2)
	require.NoError(t, err)
	defer os.Remove(providers)
	config, err := getTestConfig(providers, []string{"renku1", "renku2"})
	require.NoError(t, err)

	api, err := NewLoginServer(&config)
	apiServer, err := startTestServer(api)
	require.NoError(t, err)
	defer apiServer.Close()
	client := *http.DefaultClient
	jar, err := cookiejar.New(&cookiejar.Options{})
	require.NoError(t, err)
	client.Jar = jar

	require.NoError(t, err)
	testServerURL, err := url.Parse(strings.TrimRight(
		fmt.Sprintf("http://localhost:%d%s", config.Server.Port, config.Server.BaseURL),
		"/",
	))
	require.NoError(t, err)
	assert.Len(t, client.Jar.Cookies(testServerURL), 0)

	req, err := http.NewRequest(http.MethodGet, testServerURL.JoinPath("/login").String(), nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Len(t, client.Jar.Cookies(testServerURL), 1)

	sessionCookie := client.Jar.Cookies(testServerURL)[0]
	assert.Equal(t, commonconfig.SessionCookieName, sessionCookie.Name)
	session, err := api.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	require.NoError(t, err)
	assert.Len(t, session.TokenIDs, 2)
	assert.Len(t, session.LoginWithProviders, 0)
	assert.Len(t, session.LoginURLs, 0)
	assert.Len(t, session.CodeVerifiers, 0)
	assert.Equal(t, res.Request.URL.String(), config.DefaultAppRedirectURL)

	req, err = http.NewRequest(http.MethodGet, testServerURL.JoinPath("/logout").String(), nil)
	require.NoError(t, err)
	res, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	session, err = api.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, models.Session{}, session)
}
