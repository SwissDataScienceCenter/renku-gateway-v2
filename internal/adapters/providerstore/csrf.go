package providerstore

import (
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
)

type LoginCSRF interface {
	HashOAuthState() string
	HashOIDCNonce() string
	CheckOAuthState(string) bool
	CheckOIDCNonce(string) bool

	SetSessionNonce(s *sessions.SessionState)

	SetCookie(http.ResponseWriter, *http.Request) (*http.Cookie, error)
	ClearCookie(http.ResponseWriter, *http.Request)
}

type CSRFCookieConfig struct {
	NamePrefix string   `mapstructure:"csrf_cookie_name_prefix"`
	Secret     string   `mapstructure:"csrf_cookie_secret"`
	Domains    []string `mapstructure:"csrf_cookie_domains"`
	Path       string   `mapstructure:"csrf_cookie_path"`
	TTLMinutes int      `mapstructure:"csrf_cookie_ttl_minutes"`
}

type loginCSRF struct {
	csrf cookies.CSRF
}

func NewLoginCSRF(
	codeVerifier string,
	config CSRFCookieConfig,
) (LoginCSRF, error) {
	cookieOptions := options.Cookie{
		Name:           config.NamePrefix, // oauth2 proxy always appends _csrf to the name
		Secret:         config.Secret,
		Domains:        config.Domains,
		Path:           config.Path,
		Expire:         time.Minute * time.Duration(config.TTLMinutes),
		CSRFExpire:     time.Minute * time.Duration(config.TTLMinutes),
		CSRFPerRequest: false,
		SameSite:       "lax",
		HTTPOnly:       true,
	}

	wrappedCSRF, err := cookies.NewCSRF(&cookieOptions, codeVerifier)
	if err != nil {
		return loginCSRF{}, err
	}

	return loginCSRF{csrf: wrappedCSRF}, nil
}

func LoadCSRFCookie(
	req *http.Request,
	config CSRFCookieConfig,
) (LoginCSRF, error) {
	cookieOptions := options.Cookie{
		Name:           config.NamePrefix,
		Secret:         config.Secret,
		Domains:        config.Domains,
		Path:           config.Path,
		Expire:         time.Minute * time.Duration(config.TTLMinutes),
		CSRFExpire:     time.Minute * time.Duration(config.TTLMinutes),
		CSRFPerRequest: false,
		SameSite:       "lax",
		HTTPOnly:       true,
	}
	wrappedCSRF, err := cookies.LoadCSRFCookie(req, &cookieOptions)
	if err != nil {
		return loginCSRF{}, nil
	}
	return loginCSRF{csrf: wrappedCSRF}, nil
}

func (l loginCSRF) HashOAuthState() string {
	return l.csrf.HashOAuthState()
}

func (l loginCSRF) HashOIDCNonce() string {
	return l.csrf.HashOIDCNonce()
}

func (l loginCSRF) CheckOAuthState(state string) bool {
	return l.csrf.CheckOAuthState(state)
}

func (l loginCSRF) CheckOIDCNonce(oidcNonce string) bool {
	return l.csrf.CheckOIDCNonce(oidcNonce)
}

func (l loginCSRF) SetCookie(rw http.ResponseWriter, r *http.Request) (*http.Cookie, error) {
	return l.csrf.SetCookie(rw, r)
}

func (l loginCSRF) ClearCookie(rw http.ResponseWriter, r *http.Request) {
	l.csrf.ClearCookie(rw, r)
}

func (l loginCSRF) SetSessionNonce(s *sessions.SessionState) {
	l.csrf.SetSessionNonce(s)
}
