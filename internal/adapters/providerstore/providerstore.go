package providerstore

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/idgenerators"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

// supportedProviderTypes defines a limited set of providers from oauth2-proxy
// that are supported. This is meant to contorl the exposure we have to sudden
// changes in the oauth2 proxy APIs.
func supportedProviderTypes() map[options.ProviderType]struct{} {
	supported := make(map[options.ProviderType]struct{})
	supported[options.OIDCProvider] = struct{}{}
	supported[options.GitLabProvider] = struct{}{}
	return supported
}

// ProviderStore stores oauth2 providers from oauth2 proxy used to log users in.
// Please note that changes of the store do not trigger any migrations in the
// token or session store if some existing tokens are referencing the deleted provider.
type ProviderStore struct {
	store map[string]internalProvider
}

// Get returns the specific provider by its ID
func (p *ProviderStore) Get(id string) (Provider, bool) {
	provider, found := p.store[id]
	return provider, found
}

func (p *ProviderStore) getInternal(id string) (internalProvider, bool) {
	provider, found := p.store[id]
	return provider, found
}

func (p *ProviderStore) getMultipleInternal(ids ...string) ([]internalProvider, bool) {
	var output []internalProvider
	for _, id := range ids {
		provider, found := p.getInternal(id)
		if !found {
			return output, false
		}
		output = append(output, provider)
	}
	return output, true
}

// LoginURLs goes through a requested list of providerIDs and returns login URLs for them
func (p *ProviderStore) LoginURLs(
	callbackURL string,
	finalRedirectURL string,
	oidcNonceHash string,
	state string,
	ids ...string,
) (loginURLs []string, codeVerifiers []string, err error) {
	authProviders, found := p.getMultipleInternal(ids...)
	if !found {
		return []string{}, []string{}, fmt.Errorf("cannot find all providers")
	}

	for _, provider := range authProviders {
		extraParams := url.Values{}
		var codeChallenge, codeVerifier, codeChallengeMethod string
		// add provider specific url parameters
		if provider.wrapped.Data().CodeChallengeMethod != "" {
			codeChallengeMethod = provider.wrapped.Data().CodeChallengeMethod
			preEncodedCodeVerifier, err := encryption.Nonce(96)
			if err != nil {
				return []string{}, []string{}, err
			}
			codeVerifier = base64.RawURLEncoding.EncodeToString(preEncodedCodeVerifier)

			codeChallenge, err = encryption.GenerateCodeChallenge(
				provider.wrapped.Data().CodeChallengeMethod,
				codeVerifier,
			)
			if err != nil {
				return []string{}, []string{}, err
			}

			extraParams.Add("code_challenge", codeChallenge)
			extraParams.Add("code_challenge_method", codeChallengeMethod)
			codeVerifiers = append(codeVerifiers, codeVerifier)
		} else {
			codeVerifiers = append(codeVerifiers, "")
		}

		loginURL := provider.wrapped.GetLoginURL(
			callbackURL,
			state,
			oidcNonceHash,
			extraParams,
		)
		loginURLs = append(loginURLs, loginURL)
	}
	loginURLs = append(loginURLs, finalRedirectURL)
	return loginURLs, codeVerifiers, nil
}

// NewProviderStore parses a YAML config that defines a list of providers options
// and returns a list of oauth2 proxy providers.
func NewProviderStore(configFileName string) (ProviderStore, error) {
	idGenerator := idgenerators.ULIDGenerator{}
	store := make(map[string]internalProvider)
	providerOptions := []options.Provider{}
	err := options.LoadYAML(configFileName, &providerOptions)
	if err != nil {
		return ProviderStore{}, err
	}
	errorMsgs := validateProvidersOptions(providerOptions)
	if len(errorMsgs) > 0 {
		return ProviderStore{}, fmt.Errorf("provider configuration validation failed: %v", errorMsgs)
	}

	for _, po := range providerOptions {
		provider, err := newProvider(po, idGenerator)
		if err != nil {
			return ProviderStore{}, err
		}
		store[po.ID] = provider
	}
	return ProviderStore{store: store}, nil
}

// validateProviderOptions validates a list of provider configs
// Taken from oauth2-proxy
func validateProvidersOptions(providerOptions []options.Provider) []string {
	msgs := []string{}
	if len(providerOptions) == 0 {
		msgs = append(msgs, "at least one provider has to be defined")
	}
	providerIDs := make(map[string]struct{})

	for _, provider := range providerOptions {
		// Ensure provider IDs are unique
		if _, ok := providerIDs[provider.ID]; ok {
			msgs = append(
				msgs,
				fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ID),
			)
		}
		providerIDs[provider.ID] = struct{}{}
		// Validate provider specific options
		msgs = append(msgs, validateProviderOption(provider)...)
	}
	return msgs
}
