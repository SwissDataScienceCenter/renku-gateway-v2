package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

func sendToAuthenticate(c echo.Context, loginURL *url.URL, missingProviderIDs ...string) error {
	if c.Request().Header.Get(http.CanonicalHeaderKey("accept")) == "text/html" {
		// the requester accepts html (i.e. most likely a browser)
		redirectURL := *loginURL
		values := redirectURL.Query()
		values.Add("redirectUrl", c.Request().URL.String())
		redirectURL.RawQuery = values.Encode()
		for _, providerID := range missingProviderIDs {
			values.Add("providerId", providerID)
		}
		redirectURL.RawQuery = values.Encode()
		c.Redirect(
			http.StatusFound,
			redirectURL.String(),
		)
	}
	// the requester does not accept html
	return c.String(
		http.StatusUnauthorized,
		fmt.Sprintf(
			"not authorized, please authenticate with the following providers: %s",
			strings.Join(missingProviderIDs, ", "),
		),
	)
}
