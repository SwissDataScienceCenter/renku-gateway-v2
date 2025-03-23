package providerstore

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

func testConfigFile(config []options.Provider) (string, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	f, err := ioutil.TempFile("", id.String())
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

func testConfig() []options.Provider {
	return []options.Provider{
		{
			ClientID:     "clientID1",
			ClientSecret: "clientID1",
			ID:           "1",
			Type:         options.OIDCProvider,
			LoginURL:     "https://keycloak.test/login",
			OIDCConfig: options.OIDCOptions{
				IssuerURL:     "https://keycloak.test",
				SkipDiscovery: true,
				JwksURL:       "https://keycloak.test/jwks",
			},
		},
		{
			ClientID:     "clientID2",
			ClientSecret: "clientID2",
			ID:           "2",
			Type:         options.GitLabProvider,
			LoginURL:     "https://gitlab.com/login",
			OIDCConfig: options.OIDCOptions{
				IssuerURL:     "https://gitlab.com",
				SkipDiscovery: true,
				JwksURL:       "https://gitlab.com/jwks",
			},
		},
	}
}

func TestNewProviderStore(t *testing.T) {
	configFile, err := testConfigFile(testConfig())
	assert.NoError(t, err)
	defer os.Remove(configFile)
	p, err := NewProviderStore(configFile)
	assert.NoError(t, err)
	urls, codeVerifiers, err := p.LoginURLs(
		"https://test.com/callback",
		"https://test.com/final",
		"oidcNonceValue",
		"stateValue",
		"1",
		"2",
	)
	assert.NoError(t, err)
	assert.Len(t, urls, len(p.store)+1)
	assert.Len(t, codeVerifiers, len(p.store))
}
