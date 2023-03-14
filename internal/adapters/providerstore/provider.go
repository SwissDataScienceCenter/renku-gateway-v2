package providerstore

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

// Provider is the exact (and only) interface that external users of the adapter see
type Provider interface {
	RedeemTokens(
		req *http.Request,
		codeVerifier string,
		callBackURL string,
		csrf LoginCSRF,
	) (accessToken models.OauthToken, refreshToken models.OauthToken, err error)
}

type internalProvider struct {
	wrapped               providers.Provider
	idGenerator           models.IDGenerator
	defaultTokenExpiresIn time.Duration
	ID                    string
}

func newProvider(providerOptions options.Provider, idGenerator models.IDGenerator) (internalProvider, error) {
	// Used to assign expiration if the token obtained from the provider is missing one
	const defaultTokenExpiresIn time.Duration = time.Hour * 8
	errMsgs := validateProviderOption(providerOptions)
	if len(errMsgs) > 0 {
		return internalProvider{}, fmt.Errorf("provider options are invalid: %s", strings.Join(errMsgs, ", "))
	}
	wrappedProvider, err := providers.NewProvider(providerOptions)
	if err != nil {
		return internalProvider{}, err
	}
	return internalProvider{
		wrapped:               wrappedProvider,
		idGenerator:           idGenerator,
		defaultTokenExpiresIn: defaultTokenExpiresIn,
		ID:                    providerOptions.ID,
	}, nil
}

// validateProvider checks the validity of a specific provider config
// Taken from oauth2-proxy
func validateProviderOption(provider options.Provider) []string {
	msgs := []string{}

	supportedProviders := supportedProviderTypes()
	if _, supported := supportedProviders[provider.Type]; !supported {
		msgs = append(msgs, "provider type %s is not supported", string(provider.Type))
	}

	if provider.ID == "" {
		msgs = append(msgs, "provider has empty id: ids are required for all providers")
	}

	if provider.ClientID == "" {
		msgs = append(msgs, "provider missing setting: client-id")
	}

	// login.gov uses a signed JWT to authenticate, not a client-secret
	if provider.Type != "login.gov" {
		if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
			msgs = append(msgs, "missing setting: client-secret or client-secret-file")
		}
		if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
			_, err := os.ReadFile(provider.ClientSecretFile)
			if err != nil {
				msgs = append(msgs, "could not read client secret file: "+provider.ClientSecretFile)
			}
		}
	}

	return msgs
}

func (i internalProvider) RedeemTokens(
	req *http.Request,
	codeVerifier string,
	callBackURL string,
	csrf LoginCSRF,
) (accessToken models.OauthToken, refreshToken models.OauthToken, err error) {
	code := req.Form.Get("code")
	if code == "" {
		return models.OauthToken{}, models.OauthToken{}, providers.ErrMissingCode
	}

	s, err := i.wrapped.Redeem(req.Context(), callBackURL, code, codeVerifier)
	if err != nil {
		return models.OauthToken{}, models.OauthToken{}, err
	}

	// Force setting these in case the Provider didn't
	if s.CreatedAt == nil {
		s.CreatedAtNow()
	}
	if s.ExpiresOn == nil {
		s.ExpiresIn(i.defaultTokenExpiresIn)
	}
	// Set email
	if s.Email == "" {
		s.Email, err = i.wrapped.GetEmailAddress(req.Context(), s)
		if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
			return models.OauthToken{}, models.OauthToken{}, err
		}
	}

	state := req.Form.Get("state")

	if !csrf.CheckOAuthState(state) {
		log.Printf(
			"Invalid authentication via OAuth2: CSRF token mismatch, potential attack",
		)
		return models.OauthToken{}, models.OauthToken{}, fmt.Errorf(
			"CSRF token mismatch, potential attack. Login Failed: Unable to find a valid CSRF token. Please try again",
		)
	}

	csrf.SetSessionNonce(s)
	if !i.wrapped.ValidateSession(req.Context(), s) {
		log.Printf("Session validation failed: %s", s)
		return models.OauthToken{}, models.OauthToken{}, fmt.Errorf("Session validation failed")
	}

	// set cookie, or deny
	authorized, err := i.wrapped.Authorize(req.Context(), s)
	if err != nil || !authorized {
		log.Printf("Invalid authentication via OAuth2: unauthorized\n")
		return models.OauthToken{}, models.OauthToken{}, fmt.Errorf("Invalid session: unauthorized")
	}
	log.Printf("Authenticated via OAuth2: %s", s)

	tokenID, err := i.idGenerator.ID()
	if err != nil {
		return models.OauthToken{}, models.OauthToken{}, err
	}
	accessToken = models.OauthToken{
		ID:         tokenID,
		Value:      s.AccessToken,
		ExpiresAt:  *s.ExpiresOn,
		TokenURL:   i.wrapped.Data().RedeemURL.String(),
		ProviderID: i.ID,
		Type:       models.AccessTokenType,
	}
	refreshToken = models.OauthToken{
		ID:         tokenID,
		Value:      s.RefreshToken,
		TokenURL:   i.wrapped.Data().RedeemURL.String(),
		ProviderID: i.ID,
		Type:       models.RefreshTokenType,
	}
	return accessToken, refreshToken, nil
}
