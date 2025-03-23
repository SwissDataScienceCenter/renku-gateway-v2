package main

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/redisadapters"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/go-redis/redis/v9"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

const gitlabAuthProviderID string = "gitlab"
const renkuAuthProviderID string = "renku"

func defaultProviderIDs() []string {
	return []string{renkuAuthProviderID, gitlabAuthProviderID}
}

type renkuServicesConfig struct {
	Notebooks    *url.URL `mapstructure:"renku_services_notebooks"`
	KG           *url.URL `mapstructure:"renku_services_kg"`
	Webhook      *url.URL `mapstructure:"renku_services_webhook"`
	Core         *url.URL `mapstructure:"renku_services_core"`
	Login        *url.URL `mapstructure:"renku_services_login"`
	UIServer     *url.URL `mapstructure:"renku_services_ui_server"`
	StaticAssets *url.URL `mapstructure:"renku_services_static_assets"`
}

type metricsConfig struct {
	Enabled bool `mapstructure:"metrics_enabled"`
	Port    int  `mapstructure:"metrics_port"`
}

type SessionPersistenceConfig struct {
	Type  string                   `mapstructure:"session_persistence_type"`
	Redis commonconfig.RedisConfig `mapstructure:",squash"`
}

type TokenEncryptionConfig struct {
	Enabled   bool   `mapstructure:"token_encryption_enabled"`
	SecretKey string `mapstructure:"token_encryption_secret_key"`
}

type revProxyConfig struct {
	RenkuBaseURL           *url.URL                 `mapstructure:"renku_base_url"`
	AllowOrigin            []string                 `mapstructure:"allow_origin"`
	ExternalGitlabURL      *url.URL                 `mapstructure:"external_gitlab_url"`
	RenkuServices          renkuServicesConfig      `mapstructure:",squash"`
	SessionPersistence     SessionPersistenceConfig `mapstructure:",squash"`
	Metrics                metricsConfig            `mapstructure:",squash"`
	Port                   int                      `mapstructure:"server_port"`
	TokenEncryption        TokenEncryptionConfig    `mapstructure:",squash"`
	sessionCookieNotSecure bool
}

type PersistenceAdapter interface {
	tokenStore
	models.SessionGetter
	models.SessionSetter
	models.SessionRemover
}

// getPersistenceAdapter initializes the adapter that stores sessions and tokens.
func (r *revProxyConfig) getPersistenceAdapter() (PersistenceAdapter, error) {
	var encryptor models.Encryptor
	var err error
	if r.TokenEncryption.Enabled {
		encryptor, err = providerstore.NewGCMEncryptor(r.TokenEncryption.SecretKey)
		if err != nil {
			return nil, err
		}
	}
	switch r.SessionPersistence.Type {
	case commonconfig.SessionPersistnceTypeRedis:
		if r.SessionPersistence.Redis.IsSentinel {
			rdb := redis.NewFailoverClient(&redis.FailoverOptions{
				MasterName:       r.SessionPersistence.Redis.MasterName,
				SentinelAddrs:    r.SessionPersistence.Redis.Addresses,
				Password:         r.SessionPersistence.Redis.Password,
				DB:               r.SessionPersistence.Redis.DBIndex,
				SentinelPassword: r.SessionPersistence.Redis.Password,
			})
			return redisadapters.NewRedisAdapter(rdb, encryptor), nil
		}
		rdb := redis.NewClient(&redis.Options{
			Password: r.SessionPersistence.Redis.Password,
			DB:       r.SessionPersistence.Redis.DBIndex,
			Addr:     r.SessionPersistence.Redis.Addresses[0],
		})
		return redisadapters.NewRedisAdapter(rdb, encryptor), nil
	case commonconfig.SessionPersistnceTypeMock:
		return redisadapters.NewMockRedisAdapter(), nil
	default:
		return nil, fmt.Errorf("unrecognized persistence type %v", r.SessionPersistence.Type)
	}
}

// parseStringAsURL is used a custom decoder in Viper to convert urls provided as strings in environment
// variables to net/url.URL types.
func parseStringAsURL() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		// Check that the data is string
		if f.Kind() != reflect.String {
			return data, nil
		}

		// Check that the target type is our custom type
		if t != reflect.TypeOf(url.URL{}) {
			return data, nil
		}

		// Return the parsed value
		dataStr, ok := data.(string)
		if !ok {
			return nil, fmt.Errorf("cannot cast URL value to string")
		}
		if dataStr == "" {
			return nil, fmt.Errorf("empty values are not allowed for URLs")
		}
		url, err := url.Parse(dataStr)
		if err != nil {
			return nil, err
		}
		return url, nil
	}
}

// getConfig reads the reverse proxy configuration from environment variables.
func getConfig() (revProxyConfig, error) {
	var config revProxyConfig
	prefix := "revproxy"
	viper.SetEnvPrefix(prefix)
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(false)
	envKeysMap := &map[string]interface{}{}
	if err := mapstructure.Decode(config, &envKeysMap); err != nil {
		return revProxyConfig{}, err
	}
	for k := range *envKeysMap {
		if _, ok := os.LookupEnv(strings.ToUpper(prefix) + "_" + strings.ToUpper(k)); !ok {
			return revProxyConfig{}, fmt.Errorf(
				"environment variable %s is not defined",
				strings.ToUpper(prefix)+"_"+strings.ToUpper(k),
			)
		}
		if bindErr := viper.BindEnv(k); bindErr != nil {
			return revProxyConfig{}, bindErr
		}
	}
	err := viper.Unmarshal(
		&config,
		viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(parseStringAsURL(), mapstructure.StringToSliceHookFunc(",")),
		),
	)
	if err != nil {
		return revProxyConfig{}, err
	}
	return config, nil
}
