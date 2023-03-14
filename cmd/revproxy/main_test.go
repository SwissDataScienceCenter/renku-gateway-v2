package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/redisadapters"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const serverIDHeader string = "Server-ID"

type testRequestTracker chan *http.Request

func (t testRequestTracker) getAllRequests() []*http.Request {
	close(t)
	reqs := []*http.Request{}
	for req := range t {
		reqs = append(reqs, req)
	}
	return reqs
}

func setupTestUpstream(t *testing.T, id string, requestTracker chan<- *http.Request) (*httptest.Server, *url.URL) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(w, r.Body)
		require.NoError(t, err)
		for k := range r.Header {
			v := r.Header.Get(k)
			w.Header().Set(k, v)
		}
		r.Header.Set(serverIDHeader, id)
		requestTracker <- r
		w.WriteHeader(http.StatusOK)
	}))
	upstreamURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return srv, upstreamURL
}

func setupTestAuthServer(
	t *testing.T,
	id string,
	responseHeaders map[string]string,
	responseStatus int,
	requestTracker chan<- *http.Request,
) (*httptest.Server, *url.URL) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range responseHeaders {
			w.Header().Set(k, v)
		}
		r.Header.Set(serverIDHeader, id)
		requestTracker <- r
		w.WriteHeader(responseStatus)
	}))
	authURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return srv, authURL
}

func setupTestRevproxy(
	t *testing.T,
	upstreamServerURL *url.URL,
	externalGitlabURL *url.URL,
) (*httptest.Server, *url.URL, redisadapters.RedisAdapter) {
	config := revProxyConfig{
		RenkuBaseURL:      upstreamServerURL,
		ExternalGitlabURL: externalGitlabURL,
		RenkuServices: renkuServicesConfig{
			Notebooks:    upstreamServerURL,
			KG:           upstreamServerURL,
			Webhook:      upstreamServerURL,
			Core:         upstreamServerURL,
			Login:        upstreamServerURL,
			UIServer:     upstreamServerURL,
			StaticAssets: upstreamServerURL,
		},
		SessionPersistence: SessionPersistenceConfig{
			Type: commonconfig.SessionPersistnceTypeMock,
		},
	}
	persistence := redisadapters.NewMockRedisAdapter()
	proxy := setupServer(config, persistence)
	server := httptest.NewServer(proxy)
	proxyURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	return server, proxyURL, persistence
}

var testKcAccessToken models.OauthToken = models.OauthToken{
	ID:         "renku-access-token1",
	Value:      "renku-access-token1-value",
	ExpiresAt:  time.Now().Add(time.Hour * 8),
	TokenURL:   "https://dev.renku.ch/token",
	Type:       models.AccessTokenType,
	ProviderID: renkuAuthProviderID,
}
var testKcRefreshToken models.OauthToken = models.OauthToken{
	ID:         "renku-refresh-token1",
	Value:      "renku-refresh-token1-value",
	ExpiresAt:  time.Now().Add(time.Hour * 8),
	TokenURL:   "https://dev.renku.ch/token",
	Type:       models.RefreshTokenType,
	ProviderID: renkuAuthProviderID,
}
var testGitlabAccessToken models.OauthToken = models.OauthToken{
	ID:         "gitlab-access-token1",
	Value:      "gitlab-access-token1-value",
	ExpiresAt:  time.Now().Add(time.Hour * 8),
	TokenURL:   "https://gitlab.com/token",
	Type:       models.AccessTokenType,
	ProviderID: gitlabAuthProviderID,
}
var testGitlabRefreshToken models.OauthToken = models.OauthToken{
	ID:         "gitlab-refresh-token1",
	Value:      "gitlab-refresh-token1-value",
	ExpiresAt:  time.Now().Add(time.Hour * 8),
	TokenURL:   "https://gitlab.com/token",
	Type:       models.RefreshTokenType,
	ProviderID: gitlabAuthProviderID,
}

func notebooksExpectedGitlabKey(t *testing.T, token models.OauthToken) string {
	type gitlabCreds struct {
		Provider             string `json:"provider"`
		AuthorizationHeader  string `json:"AuthorizationHeader"`
		AccessTokenExpiresAt int64  `json:"AccessTokenExpiresAt"`
	}
	creds := map[string]gitlabCreds{}
	gitURL, err := url.Parse(token.TokenURL)
	if err != nil {
		require.NoError(t, err)
	}
	if strings.HasPrefix(gitURL.RequestURI(), "/gitlab") {
		gitURL.Path = "/gitlab"
		gitURL.RawPath = "/gitlab"
	} else {
		gitURL.Path = ""
		gitURL.RawPath = ""
	}
	gitURL.RawQuery = ""
	gitURL.RawFragment = ""
	creds[gitURL.String()] = gitlabCreds{
		Provider:             token.ProviderID,
		AuthorizationHeader:  "bearer " + token.Value,
		AccessTokenExpiresAt: token.ExpiresAt.Unix(),
	}
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		require.NoError(t, err)
	}
	return base64.StdEncoding.EncodeToString(credsJSON)
}

type TestResults struct {
	Path                     string
	VisitedServerIDs         []string
	ResponseHeaders          map[string]string
	Non200ResponseStatusCode int
	IgnoreErrors             bool
	FinalRequestHeaders      map[string]string
	FinalRequestCookies      map[string]string
}

type TestCase struct {
	Path                         string
	QueryParams                  map[string]string
	Non200AuthResponseStatusCode int
	ExternalGitlab               bool
	Expected                     TestResults
	SessionID                    string
	Tokens                       []models.OauthToken
	InjectUpstreamHostInHeader   bool
	InjectGitlabHostInHeader     bool
}

func uniqueSlice(slice []string) []string {
	// create a map with all the values as key
	uniqMap := make(map[string]struct{})
	for _, v := range slice {
		uniqMap[v] = struct{}{}
	}

	// turn the map keys into a slice
	uniqSlice := make([]string, 0, len(uniqMap))
	for v := range uniqMap {
		uniqSlice = append(uniqSlice, v)
	}
	return uniqSlice
}

func ParametrizedRouteTest(scenario TestCase) func(*testing.T) {
	return func(t *testing.T) {
		// Setup and start
		requestTracker := make(testRequestTracker, 20)
		upstream, upstreamURL := setupTestUpstream(t, "upstream", requestTracker)
		ctx := context.Background()

		var (
			gitlab    *httptest.Server
			gitlabURL *url.URL
		)
		if scenario.ExternalGitlab {
			gitlab, gitlabURL = setupTestUpstream(t, "gitlab", requestTracker)
			defer gitlab.Close()
		}
		proxy, proxyURL, persistenceAdapter := setupTestRevproxy(t, upstreamURL, gitlabURL)
		defer upstream.Close()
		defer proxy.Close()

		// setup session and tokens
		tokenIDs := []string{}
		for _, token := range scenario.Tokens {
			var err error
			switch token.Type {
			case models.AccessTokenType:
				err = persistenceAdapter.SetAccessToken(ctx, token)
			case models.RefreshTokenType:
				err = persistenceAdapter.SetRefreshToken(ctx, token)
			}
			require.NoError(t, err)
			tokenIDs = append(tokenIDs, token.ID)
		}
		tokenIDs = uniqueSlice(tokenIDs)
		session := models.Session{
			ID:        scenario.SessionID,
			TokenIDs:  tokenIDs,
			ExpiresAt: time.Now().Add(time.Hour * 8),
		}
		err := persistenceAdapter.SetSession(ctx, session)
		require.NoError(t, err)

		// Make request through proxy
		testURL := proxyURL.JoinPath(scenario.Path)
		testURLQuery := testURL.Query()
		for k, v := range scenario.QueryParams {
			testURLQuery.Add(k, v)
		}
		testURL.RawQuery = testURLQuery.Encode()
		testReq, err := http.NewRequest(http.MethodGet, testURL.String(), nil)
		require.NoError(t, err)
		testReq.AddCookie(session.Cookie(commonconfig.SessionCookieName, "", false))
		res, err := http.DefaultClient.Do(testReq)
		reqs := requestTracker.getAllRequests()

		// Assert the request was routed as expected
		if !scenario.Expected.IgnoreErrors {
			require.NoError(t, err)
		}
		if scenario.Expected.Non200ResponseStatusCode != 0 {
			assert.Equal(t, scenario.Expected.Non200ResponseStatusCode, res.StatusCode)
		} else {
			assert.Equal(t, http.StatusOK, res.StatusCode)
		}
		assert.Len(t, reqs, len(scenario.Expected.VisitedServerIDs))
		for ireq, req := range reqs {
			assert.Equal(t, scenario.Expected.VisitedServerIDs[ireq], req.Header.Get(serverIDHeader))
		}
		for hdrKey, hdrValue := range scenario.Expected.ResponseHeaders {
			assert.Equal(t, hdrValue, res.Header.Get(hdrKey))
		}
		if scenario.Expected.Path != "" {
			expectedURL, err := url.Parse(scenario.Expected.Path)
			require.NoError(t, err)
			if len(scenario.QueryParams) > 0 {
				expectedURL.RawQuery = testURLQuery.Encode()
			}
			assert.Equal(t, expectedURL, reqs[len(reqs)-1].URL)
		}
		finalReq := reqs[len(reqs)-1]
		for cookieName, cookieValExpected := range scenario.Expected.FinalRequestCookies {
			cookie, err := finalReq.Cookie(cookieName)
			require.NoError(t, err)
			assert.Equal(t, cookieValExpected, cookie.Value)
		}
		for headerName, headerValExpected := range scenario.Expected.FinalRequestHeaders {
			assert.Equal(t, headerValExpected, finalReq.Header.Get(headerName))
		}
		if scenario.InjectUpstreamHostInHeader {
			assert.Equal(t, upstreamURL.Host, finalReq.Header.Get("Renku-Gateway-Upstream-Host"))
		}
		if scenario.InjectGitlabHostInHeader {
			assert.Equal(t, gitlabURL.Host, finalReq.Header.Get("Renku-Gateway-Upstream-Host"))
		}
	}
}

func TestInternalSvcRoutes(t *testing.T) {
	testCases := []TestCase{
		{
			Path: "/api/auth/test",
			Expected: TestResults{
				Path:                "/api/auth/test",
				VisitedServerIDs:    []string{"upstream"},
				FinalRequestCookies: map[string]string{commonconfig.SessionCookieName: "test-session"},
			},
			Tokens: []models.OauthToken{
				testKcAccessToken,
				testKcRefreshToken,
				testGitlabAccessToken,
				testGitlabRefreshToken,
			},
			SessionID: "test-session",
		},
		{
			Path: "/api/auth",
			Expected: TestResults{
				Path:                "/api/auth",
				VisitedServerIDs:    []string{"upstream"},
				FinalRequestCookies: map[string]string{commonconfig.SessionCookieName: "test-session"},
			},
			SessionID: "test-session",
			Tokens: []models.OauthToken{
				testKcAccessToken,
				testKcRefreshToken,
				testGitlabAccessToken,
				testGitlabRefreshToken,
			},
		},
		{
			Path: "/api/auth/test",
			Expected: TestResults{
				Path:                "/api/auth/test",
				VisitedServerIDs:    []string{"upstream"},
				FinalRequestCookies: map[string]string{commonconfig.SessionCookieName: "test-session"},
			},
			SessionID: "test-session",
		},
		{
			Path: "/api/auth",
			Expected: TestResults{
				Path:             "/api/auth",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path: "/api/notebooks/test/something",
			Expected: TestResults{
				Path:             "/notebooks/test/something",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Renku-Auth-Access-Token":           "",
					"Renku-Auth-Id-Token":               "",
					"Renku-Auth-Refresh-Token":          "",
					"Renku-Auth-Git-Credentials":        "",
					commonconfig.AnonymousUserHeaderKey: commonconfig.AnonymousUserHeaderPrefix + "anon-session-id",
				},
			},
			SessionID: "anon-session-id",
		},
		{
			Path: "/api/notebooks/test/acceptedAuth",
			Expected: TestResults{
				Path:             "/notebooks/test/acceptedAuth",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Renku-Auth-Access-Token":           testKcAccessToken.Value,
					"Renku-Auth-Id-Token":               testKcAccessToken.Value,
					"Renku-Auth-Refresh-Token":          testKcRefreshToken.Value,
					"Renku-Auth-Git-Credentials":        notebooksExpectedGitlabKey(t, testGitlabAccessToken),
					commonconfig.AnonymousUserHeaderKey: "",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testKcAccessToken,
				testKcRefreshToken,
				testGitlabAccessToken,
				testGitlabRefreshToken,
			},
		},
		{
			Path:     "/api/notebooks",
			Expected: TestResults{Path: "/notebooks", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path: "/ui-server/api/notebooks/test",
			Expected: TestResults{
				Path:             "/notebooks/test",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Renku-Auth-Access-Token":           "",
					"Renku-Auth-Id-Token":               "",
					"Renku-Auth-Refresh-Token":          "",
					"Renku-Auth-Git-Credentials":        "",
					commonconfig.AnonymousUserHeaderKey: commonconfig.AnonymousUserHeaderPrefix + "anon-session-id",
				},
			},
			SessionID: "anon-session-id",
		},
		{
			Path: "/ui-server/api/notebooks",
			Expected: TestResults{
				Path:             "/notebooks",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Renku-Auth-Access-Token":           testKcAccessToken.Value,
					"Renku-Auth-Id-Token":               testKcAccessToken.Value,
					"Renku-Auth-Refresh-Token":          testKcRefreshToken.Value,
					"Renku-Auth-Git-Credentials":        notebooksExpectedGitlabKey(t, testGitlabAccessToken),
					commonconfig.AnonymousUserHeaderKey: "",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testKcAccessToken,
				testKcRefreshToken,
				testGitlabAccessToken,
				testGitlabRefreshToken,
			},
		},
		{
			Path: "/api/projects/123456/graph/status/something/else",
			Expected: TestResults{
				Path:             "/projects/123456/events/status/something/else",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization": "Bearer " + testGitlabAccessToken.Value,
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
		},
		{
			Path:        "/api/projects/123456/graph/status",
			QueryParams: map[string]string{"test1": "value1", "test2": "value2"},
			Expected: TestResults{
				Path:             "/projects/123456/events/status",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path: "/api/projects/123456/graph/webhooks/something/else",
			Expected: TestResults{
				Path:             "/projects/123456/webhooks/something/else",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path:        "/api/projects/123456/graph/webhooks",
			QueryParams: map[string]string{"test1": "value1", "test2": "value2"},
			Expected:    TestResults{Path: "/projects/123456/webhooks", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:     "/api/datasets/test",
			Expected: TestResults{Path: "/knowledge-graph/datasets/test", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:        "/api/datasets",
			QueryParams: map[string]string{"test1": "value1", "test2": "value2"},
			Expected:    TestResults{Path: "/knowledge-graph/datasets", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:     "/api/kg/test",
			Expected: TestResults{Path: "/knowledge-graph/test", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:        "/api/kg",
			QueryParams: map[string]string{"test1": "value1", "test2": "value2"},
			Expected:    TestResults{Path: "/knowledge-graph", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:     "/api/renku/test",
			Expected: TestResults{Path: "/renku/test", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:        "/api/renku",
			QueryParams: map[string]string{"test1": "value1", "test2": "value2"},
			Expected:    TestResults{Path: "/renku", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/gitlab/test/something",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/test/something", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/gitlab",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/user/test/something",
			ExternalGitlab: true,
			Expected: TestResults{
				Path:             "/api/v4/user/test/something",
				VisitedServerIDs: []string{"gitlab"},
			},
		},
		{
			Path:           "/api/user/test/something",
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/gitlab/api/v4/user/test/something",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path:           "/api",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab/api/v4", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/api/v4", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/direct/test",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/test", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/direct",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/direct/test",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab/test", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api/direct",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api/graphql/test",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/api/graphql/test", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/graphql",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/api/graphql", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/graphql/test",
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/gitlab/api/graphql/test",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path:           "/api/graphql",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab/api/graphql", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api/repos/test",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/test", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/repos",
			ExternalGitlab: true,
			Expected:       TestResults{Path: "/", VisitedServerIDs: []string{"gitlab"}},
		},
		{
			Path:           "/api/repos/test",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab/test", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api/repos",
			ExternalGitlab: false,
			Expected:       TestResults{Path: "/gitlab", VisitedServerIDs: []string{"upstream"}},
		},
		{
			Path:           "/api/projects/some.username%2Ftest-project",
			QueryParams:    map[string]string{"statistics": "false", "doNotTrack": "true"},
			ExternalGitlab: true,
			Expected: TestResults{
				Path:             "/api/v4/projects/some.username%2Ftest-project",
				VisitedServerIDs: []string{"gitlab"},
			},
		},
		{
			Path:           "/api/projects/some.username%2Ftest-project",
			QueryParams:    map[string]string{"statistics": "false", "doNotTrack": "true"},
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/gitlab/api/v4/projects/some.username%2Ftest-project",
				VisitedServerIDs: []string{"upstream"},
			},
		},
		{
			Path:           "/ui-server/api/last-searches/4",
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/ui-server/api/last-searches/4",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization": "bearer user-session-id",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
		},
		{
			Path:           "/ui-server/api/last-projects/4",
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/ui-server/api/last-projects/4",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization": "bearer user-session-id",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
		},
		{
			Path:           "/ui-server/api/renku/cache.files_upload",
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/ui-server/api/renku/cache.files_upload",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization":                        "bearer user-session-id",
					"Renku-Gateway-Upstream-Authorization": "bearer " + testGitlabAccessToken.Value,
					"Renku-Gateway-Upstream-Path":          "/api/renku/cache.files_upload",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
			InjectUpstreamHostInHeader: true,
		},
		{
			Path:           "/ui-server/api/kg/entities/test",
			QueryParams:    map[string]string{"query": "testVal"},
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/ui-server/api/kg/entities/test",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization":                        "bearer user-session-id",
					"Renku-Gateway-Upstream-Authorization": "bearer " + testGitlabAccessToken.Value,
					"Renku-Gateway-Upstream-Path":          "/knowledge-graph/entities/test?query=testVal",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
			InjectUpstreamHostInHeader: true,
		},
		{
			Path:           "/ui-server/api/projects/some.username%2Ftest-project",
			QueryParams:    map[string]string{"query": "testVal"},
			ExternalGitlab: false,
			Expected: TestResults{
				Path:             "/ui-server/api/projects/some.username%2Ftest-project",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization":                        "bearer user-session-id",
					"Renku-Gateway-Upstream-Authorization": "bearer " + testGitlabAccessToken.Value,
					"Renku-Gateway-Upstream-Path":          "/gitlab/api/v4/projects/some.username%2Ftest-project?query=testVal",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
			InjectUpstreamHostInHeader: true,
		},
		{
			Path:           "/ui-server/api/projects/some.username%2Ftest-project",
			QueryParams:    map[string]string{"query": "testVal"},
			ExternalGitlab: true,
			Expected: TestResults{
				Path:             "/ui-server/api/projects/some.username%2Ftest-project",
				VisitedServerIDs: []string{"upstream"},
				FinalRequestHeaders: map[string]string{
					"Authorization":                        "bearer user-session-id",
					"Renku-Gateway-Upstream-Authorization": "bearer " + testGitlabAccessToken.Value,
					"Renku-Gateway-Upstream-Path":          "/api/v4/projects/some.username%2Ftest-project?query=testVal",
				},
			},
			SessionID: "user-session-id",
			Tokens: []models.OauthToken{
				testGitlabAccessToken,
			},
			InjectGitlabHostInHeader: true,
		},
	}
	for _, testCase := range testCases {
		// Test names show up poorly in vscode if the name contains "/"
		t.Run(strings.ReplaceAll(testCase.Path, "/", "|"), ParametrizedRouteTest(testCase))
	}
}
