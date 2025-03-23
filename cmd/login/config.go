package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/providerstore"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/adapters/redisadapters"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/commonconfig"
	"github.com/SwissDataScienceCenter/renku-gateway-v2/internal/models"
	"github.com/go-redis/redis/v9"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type SessionPersistenceConfig struct {
	Type  string                   `mapstructure:"session_persistence_type"`
	Redis commonconfig.RedisConfig `mapstructure:",squash"`
}

type ServerConfig struct {
	Port    int    `mapstructure:"server_port"`
	BaseURL string `mapstructure:"server_base_url"`
}

type TokenEncryptionConfig struct {
	Enabled   bool   `mapstructure:"token_encryption_enabled"`
	SecretKey string `mapstructure:"token_encryption_secret_key"`
}

type LoginServerConfig struct {
	DefaultProviderIDs     []string                       `mapstructure:"default_provider_ids"`
	DefaultAppRedirectURL  string                         `mapstructure:"default_app_redirect_url"`
	CallbackURL            string                         `mapstructure:"callback_url"`
	CSRFCookie             providerstore.CSRFCookieConfig `mapstructure:",squash"`
	Server                 ServerConfig                   `mapstructure:",squash"`
	SessionPersistence     SessionPersistenceConfig       `mapstructure:",squash"`
	TokenEncryption        TokenEncryptionConfig          `mapstructure:",squash"`
	ProviderConfigFile     string                         `mapstructure:"provider_config_file"`
	AllowOrigin            []string                       `mapstructure:"allow_origin"`
	sessionCookieNotSecure bool
}

// CSRFCookieName returns the name of the cookie used for CSRF protection during login.
func (c LoginServerConfig) CSRFCookieName() string {
	// the oauth2-proxy library always appends "_csrf" to the cookie name
	return c.CSRFCookie.NamePrefix + "_csrf"
}

// PersistenceAdapter intializes the store that manages sessions and tokens
func (c LoginServerConfig) PersistenceAdapter() (SessionTokenStore, error) {
	var encryptor models.Encryptor
	var err error
	if c.TokenEncryption.Enabled {
		encryptor, err = providerstore.NewGCMEncryptor(c.TokenEncryption.SecretKey)
		if err != nil {
			return nil, err
		}
	}
	switch c.SessionPersistence.Type {
	case commonconfig.SessionPersistnceTypeRedis:
		if c.SessionPersistence.Redis.IsSentinel {
			rdb := redis.NewFailoverClient(&redis.FailoverOptions{
				MasterName:       c.SessionPersistence.Redis.MasterName,
				SentinelAddrs:    c.SessionPersistence.Redis.Addresses,
				Password:         c.SessionPersistence.Redis.Password,
				DB:               c.SessionPersistence.Redis.DBIndex,
				SentinelPassword: c.SessionPersistence.Redis.Password,
			})
			return redisadapters.NewRedisAdapter(rdb, encryptor), nil
		}
		rdb := redis.NewClient(&redis.Options{
			Password: c.SessionPersistence.Redis.Password,
			DB:       c.SessionPersistence.Redis.DBIndex,
			Addr:     c.SessionPersistence.Redis.Addresses[0],
		})
		return redisadapters.NewRedisAdapter(rdb, encryptor), nil
	case commonconfig.SessionPersistnceTypeMock:
		return redisadapters.NewMockRedisAdapter(), nil
	default:
		return nil, fmt.Errorf("unrecognized persistence type %v", c.SessionPersistence.Type)
	}
}

// ProviderStore initializes a list of login providers used by the login server. It is one of the main
// touch points with the oauth2 proxy library.
func (c LoginServerConfig) ProviderStore() (ProviderStore, error) {
	store, err := providerstore.NewProviderStore(c.ProviderConfigFile)
	if err != nil {
		return nil, err
	}
	return &store, nil
}

// getConfig generates a configuration for the login server based on environment variables.
func getConfig() (LoginServerConfig, error) {
	var config LoginServerConfig
	prefix := "login"
	viper.SetEnvPrefix(prefix)
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(false)
	envKeysMap := &map[string]interface{}{}
	if err := mapstructure.Decode(config, &envKeysMap); err != nil {
		return LoginServerConfig{}, err
	}
	for k := range *envKeysMap {
		if _, ok := os.LookupEnv(strings.ToUpper(prefix) + "_" + strings.ToUpper(k)); !ok {
			return LoginServerConfig{}, fmt.Errorf(
				"environment variable %s is not defined",
				strings.ToUpper(prefix)+"_"+strings.ToUpper(k),
			)
		}
		if bindErr := viper.BindEnv(k); bindErr != nil {
			return LoginServerConfig{}, bindErr
		}
	}
	err := viper.Unmarshal(&config, viper.DecodeHook(mapstructure.StringToSliceHookFunc(",")))
	if err != nil {
		return LoginServerConfig{}, fmt.Errorf("unable to decode config into struct, %v", err)
	}
	// Check encryption key lengths
	if config.TokenEncryption.Enabled && len([]byte(config.TokenEncryption.SecretKey)) != 32 {
		return LoginServerConfig{}, fmt.Errorf(
			"token encryption key has to be 32 bytes long, the provided one is %d long",
			len([]byte(config.TokenEncryption.SecretKey)),
		)
	}
	if len([]byte(config.CSRFCookie.Secret)) != 32 {
		return LoginServerConfig{}, fmt.Errorf(
			"csrf cookie encryption key has to be 32 bytes long, the provided one is %d long",
			len([]byte(config.CSRFCookie.Secret)),
		)
	}
	return config, nil
}
