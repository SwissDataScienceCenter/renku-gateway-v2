package main

import (
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// proxyFromURL middleware creates a proxy that forwards requests to the specified URL
func proxyFromURL(upstreamURL *url.URL) echo.MiddlewareFunc {
	config := middleware.ProxyConfig{
		Balancer: middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{
			{
				Name: upstreamURL.String(),
				URL:  upstreamURL,
			}}),
	}
	return middleware.ProxyWithConfig(config)
}
