// nolint:lll
// Package main contains the definition of all routes, proxying and authentication
// performed by the reverse proxy that is part of the Renku gateway.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/commonmiddlewares"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func setupServer(config revProxyConfig, persistenceAdapter PersistenceAdapter) *echo.Echo {
	// Intialize common reverse proxy middlewares
	staticAssetsProxy := proxyFromURL(config.RenkuServices.StaticAssets)
	var gitlabProxy, gitlabProxyHost echo.MiddlewareFunc
	if config.ExternalGitlabURL != nil {
		gitlabProxy = proxyFromURL(config.ExternalGitlabURL)
		gitlabProxyHost = setHost(config.ExternalGitlabURL.Host)
	} else {
		gitlabProxy = proxyFromURL(config.RenkuBaseURL)
		gitlabProxyHost = setHost(config.RenkuBaseURL.Host)
	}
	notebooksProxy := proxyFromURL(config.RenkuServices.Notebooks)
	loginSvcProxy := proxyFromURL(config.RenkuServices.Login)
	coreProxy := proxyFromURL(config.RenkuServices.Core)
	kgProxy := proxyFromURL(config.RenkuServices.KG)
	webhookProxy := proxyFromURL(config.RenkuServices.Webhook)
	uiServerProxy := proxyFromURL(config.RenkuServices.UIServer)
	logger := middleware.Logger()

	// Initialize common authentication middleware
	notebooksKcCredInject := (&CredsInjectionMiddleware{persistenceAdapter, config.RenkuServices.Login, true, true}).Middleware(notebooksKcInjector)
	notebooksGitlabCredInject := (&CredsInjectionMiddleware{persistenceAdapter, config.RenkuServices.Login, false, true}).Middleware(notebooksGitlabInjector)
	gitlabCredInject := (&CredsInjectionMiddleware{persistenceAdapter, config.RenkuServices.Login, false, false}).Middleware(gitlabInjector)
	coreSvcKcCredInject := (&CredsInjectionMiddleware{persistenceAdapter, config.RenkuServices.Login, false, false}).Middleware(coreKcInjector)
	uiServerGitlabCredInject := (&CredsInjectionMiddleware{persistenceAdapter, config.RenkuServices.Login, false, false}).Middleware(uiServerGitlabInjector)

	// Optional CORS setup
	corsConfig := middleware.DefaultCORSConfig
	if len(config.AllowOrigin) > 0 {
		corsConfig.AllowOrigins = config.AllowOrigin
	}
	// Middleware that handles the user sessions creation, deletion, retrieval
	sessionMw := commonmiddlewares.NewSessionMiddleware(
		persistenceAdapter,
		commonconfig.SessionCookieName,
		!config.sessionCookieNotSecure,
	).Middleware(models.Default)

	// Server instance
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash(), uiServerPathRewrite())
	e.Use(middleware.Recover(), middleware.CORSWithConfig(corsConfig))

	// Routing for Renku services
	e.Group("/api/auth", logger, sessionMw, loginSvcProxy)
	e.Group("/api/notebooks", logger, sessionMw, notebooksKcCredInject, notebooksGitlabCredInject, notebooksInjectAnonymousUserID, noCookies, stripPrefix("/api"), notebooksProxy)
	e.Group("/api/projects/:projectID/graph", logger, sessionMw, gitlabCredInject, noCookies, kgProjectsGraphRewrites, webhookProxy,)
	e.Group("/api/datasets", logger, sessionMw, noCookies, regexRewrite("^/api(.*)", "/knowledge-graph$1"), kgProxy)
	e.Group("/api/kg", logger, sessionMw, gitlabCredInject, noCookies, regexRewrite("^/api/kg(.*)", "/knowledge-graph$1"), kgProxy)
	e.Group("/api/renku", logger, sessionMw, coreSvcKcCredInject, gitlabCredInject, noCookies, stripPrefix("/api"), coreProxy)
	
	// UI server webssockets
	e.Group("/ui-server/ws", logger, sessionMw, uiServerInjectSessionId, uiServerProxy)
	// Some routes need to go to the UI server before they go to the specific Renku service
	e.Group("/ui-server/api/last-searches/:length", logger, sessionMw, uiServerInjectSessionId, uiServerProxy)
	e.Group("/ui-server/api/last-projects/:length", logger, sessionMw, uiServerInjectSessionId, uiServerProxy)
	e.Group("/ui-server/api/renku/cache.files_upload", logger, sessionMw, uiServerGitlabCredInject, gitlabCredInject, uiServerInjectSessionId, uiServerUpstreamCoreLocation(config.RenkuServices.Core.Host), uiServerProxy)
	e.Group("/ui-server/api/kg/entities", logger, sessionMw, uiServerGitlabCredInject, uiServerInjectSessionId, uiServerUpstreamKgLocation(config.RenkuServices.KG.Host), uiServerProxy)

	// Routes that end up proxied to Gitlab
	if config.ExternalGitlabURL != nil {
		// Redirect "old" style bundled /gitlab pathing if an external Gitlab is used
		e.Group("/gitlab", logger, sessionMw, stripPrefix("/gitlab"), gitlabProxyHost, gitlabProxy)
		e.Group("/api/graphql", logger, sessionMw, gitlabCredInject, gitlabProxyHost, gitlabProxy)
		e.Group("/api/direct", logger, sessionMw, stripPrefix("/api/direct"), gitlabProxyHost, gitlabProxy)
		e.Group("/api/repos", logger, sessionMw, gitlabCredInject, noCookies, stripPrefix("/api/repos"), gitlabProxyHost, gitlabProxy)
		e.Group("/ui-server/api/projects/:projectName", logger, sessionMw, uiServerGitlabCredInject, uiServerInjectSessionId, uiServerUpstreamExternalGitlabLocation(config.ExternalGitlabURL.Host), uiServerProxy)
		// If nothing is matched in any other more specific /api route then fall back to Gitlab
		e.Group("/api", logger, sessionMw, gitlabCredInject, noCookies, regexRewrite("^/api(.*)", "/api/v4$1"), gitlabProxyHost, gitlabProxy)
	} else {
		e.Group("/api/graphql", logger, sessionMw, gitlabCredInject, regexRewrite("^(.*)", "/gitlab$1"), gitlabProxyHost, gitlabProxy)
		e.Group("/api/direct", logger, sessionMw, regexRewrite("^/api/direct(.*)", "/gitlab$1"), gitlabProxyHost, gitlabProxy)
		e.Group("/api/repos", logger, sessionMw, gitlabCredInject, noCookies, regexRewrite("^/api/repos(.*)", "/gitlab$1"), gitlabProxyHost, gitlabProxy)
		e.Group("/ui-server/api/projects/:projectName", logger, sessionMw, uiServerGitlabCredInject, uiServerInjectSessionId, uiServerUpstreamInternalGitlabLocation(config.RenkuBaseURL.Host), uiServerProxy)
		// If nothing is matched in any other more specific /api route then fall back to Gitlab
		e.Group("/api", logger, sessionMw, gitlabCredInject, noCookies, regexRewrite("^/api(.*)", "/gitlab/api/v4$1"), gitlabProxyHost, gitlabProxy)
	}

	// If nothing is matched from any of the routes above then fall back to the UI
	e.Group("/", logger, sessionMw, staticAssetsProxy)

	// Reverse proxy specific endpoints
	rp := e.Group("/revproxy")
	rp.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e
}

func main() {
	config, err := getConfig()
	if err != nil {
		log.Fatalln(err)
	}
	persistenceAdapter, err := config.getPersistenceAdapter()
	if err != nil {
		log.Fatalln(err)
	}
	e := setupServer(config, persistenceAdapter)
	// Start API server
	go func() {
		if err := e.Start(fmt.Sprintf(":%d", config.Port)); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal(err)
		}
	}()
	// Start metrics server if enabled
	var metricsServer *echo.Echo
	if config.Metrics.Enabled {
		metricsServer = getMetricsServer(e)
		go func() {
			if err := metricsServer.Start(fmt.Sprintf(":%d", config.Metrics.Port)); err != nil &&
				err != http.ErrServerClosed {
				metricsServer.Logger.Fatal(err)
			}
		}()
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit // Wait for interrupt signal from OS
	// Start shutting down servers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
	if config.Metrics.Enabled {
		if err := metricsServer.Shutdown(ctx); err != nil {
			metricsServer.Logger.Fatal(err)
		}
	}
}
