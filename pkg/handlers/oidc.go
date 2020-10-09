package handlers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	oidc "github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	secureCookie "github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type (
	// OidcClient is the configuration data for a client
	OidcClient struct {
		Name             string
		Provider         *oidc.Provider
		ClientID         string
		ClientSecret     string
		NoRedirect       bool
		AllowedRedirects []string
		Scopes           []string
		CookieDomain     string
		CookieSecret     string
		logger           *logrus.Logger
	}
	// Oidc is the configuration data
	Oidc struct {
		clients     map[string]*OidcClient
		stateStorer StateStorer
		externalURL string
		logger      *logrus.Logger
	}
)

// StateStorer is the contract used for storing state information temporarily
type StateStorer interface {
	SaveRedirectURIForClient(string, string) (string, error)
	GetRedirectURI(string) (string, string, error)
}

const cookieName = "jwt"

// NewOidcHandler creates a new object for handling all oidc authorisation requests.
func NewOidcHandler(config string, externalURL string, stateStorer StateStorer, logger *logrus.Logger) (*Oidc, error) {

	var clientConfigs []struct {
		Profile          string   `yaml:"profile"`
		Provider         string   `yaml:"provider"`
		ClientID         string   `yaml:"clientID"`
		ClientSecret     string   `yaml:"clientSecret"`
		NoRedirect       bool     `yaml:"noRedirect"`
		AllowedRedirects []string `yaml:"allowedRedirects"`
		Scopes           []string `yaml:"scopes"`
		CookieDomain     string   `yaml:"cookieDomain"`
		CookieSecret     string   `yaml:"cookieSecret"`
	}
	err := yaml.Unmarshal([]byte(config), &clientConfigs)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse OIDC client config")
	}

	// Initialize each unique provider
	providers := make(map[string]*oidc.Provider)
	clients := make(map[string]*OidcClient)

	for _, c := range clientConfigs {
		if len(c.Scopes) == 0 {
			c.Scopes = []string{oidc.ScopeOpenID}
		}
		_, ok := providers[c.Provider]
		if !ok {
			logger.Info("Initialising OIDC discovery endpoint", c.Provider)
			providers[c.Provider], err = oidc.NewProvider(context.Background(), c.Provider)
			if err != nil {
				logger.Error("Unable to initialise provider", err)
				return nil, errors.Wrap(err, "Unable to initialise provider")
			}
		}
		clients[c.Profile] = &OidcClient{
			Name:             c.Profile,
			Provider:         providers[c.Provider],
			ClientID:         c.ClientID,
			ClientSecret:     c.ClientSecret,
			NoRedirect:       c.NoRedirect,
			AllowedRedirects: c.AllowedRedirects,
			Scopes:           c.Scopes,
			CookieDomain:     c.CookieDomain,
			CookieSecret:     c.CookieSecret,
			logger:           logger,
		}
		logger.WithFields(logrus.Fields{
			"method":   "NewOidcHandler",
			"profile":  c.Profile,
			"clientID": c.ClientID,
			"provider": c.Provider,
		}).Debug("Adding configuration.")
	}

	if len(clients) == 0 {
		return nil, errors.New("No OIDC clients configured")
	}
	return &Oidc{clients, stateStorer, externalURL, logger}, nil
}

// helpers
var verify = func(token string, c OidcClient) error {
	idTokenVerifier := c.Provider.Verifier(
		&oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{"RS256"}},
	)
	_, err := idTokenVerifier.Verify(context.Background(), token)
	return err
}

func (c OidcClient) verifyToken(token string) error {
	return verify(token, c)
}

func (c OidcClient) redirectURL(r *http.Request) string {
	c.logger.WithFields(logrus.Fields{
		"method":         "redirectURL",
		"original-url":   r.Header.Get("X-Original-Url"),
		"redirect-param": r.URL.Query().Get("rd"),
	}).Debug("RedirectURL")

	for name, headers := range r.Header {
		for _, header := range headers {
			c.logger.WithFields(logrus.Fields{
				"method": "redirectURL",
				"header": name,
				"value":  header,
			}).Debug("HEADER")
		}
	}

	var rd string
	if !c.NoRedirect {
		rd = r.URL.Query().Get("rd")
	}

	return rd
	// return fmt.Sprintf("%v://%v/auth/callback", r.URL.Scheme, host), fmt.Sprintf("clientid=%v,rd=%v", c.ClientID, rd)
}

func (c OidcClient) oAuth2Config(redirect string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     getEndpoint(c),
		RedirectURL:  redirect,
		Scopes:       c.Scopes,
	}
}

var getEndpoint = func(c OidcClient) oauth2.Endpoint {
	return c.Provider.Endpoint()
}

// Handlers

var getProfile = func(r *http.Request, paramName string) string {
	return chi.URLParam(r, "profile")
}

// VerifyHandler takes care of verifying if the user is authenticated.VerifyHandler
// Id does this by querying a cookie named after the specific config profile name.
func (o Oidc) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	profile := getProfile(r, "profile")
	o.logger.WithFields(logrus.Fields{
		"method":  "VerifyHandler",
		"profile": profile,
	}).Debug("Verifying for profile.")

	if config, ok := o.clients[profile]; ok {
		hashKey := []byte(config.CookieSecret)
		s := secureCookie.New(hashKey, nil)

		cookie, err := r.Cookie(config.Name)
		if err != nil {
			o.logger.WithFields(logrus.Fields{
				"method": "VerifyHandler",
				"error":  err.Error(),
			}).Warn("Something wrong with the cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var token string
		err = s.Decode(config.Name, cookie.Value, &token)
		o.logger.WithFields(logrus.Fields{
			"method": "VerifyHandler",
			"token":  token,
			"error":  err,
		}).Debug("Decode cookie")
		if token != "" {
			err = config.verifyToken(token)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	o.logger.WithFields(logrus.Fields{
		"method":  "VerifyHandler",
		"profile": profile,
	}).Warn("Unable to find profile in configuration")
	w.WriteHeader(http.StatusForbidden)
}

// SigninHandler signs a user in via the oauth provider set in the signin request
func (o Oidc) SigninHandler(w http.ResponseWriter, r *http.Request) {
	profile := getProfile(r, "profile")
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
	}).Debug("Signing in")

	config, ok := o.clients[profile]
	if !ok {
		// There's been a configuration error.
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
		}).Warn("Unable to find profile in configuration")

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Configuration error")
		return
	}

	// The request was ok, figure out if we are already signed in, and if not, redirect to our oauth provider.
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
		"config":  config,
	}).Debug("Found config for profile.")

	redirectTo := config.redirectURL(r)
	allowed := false
	for i := range config.AllowedRedirects {
		re := regexp.MustCompile(config.AllowedRedirects[i])
		allowed = allowed || re.MatchString(redirectTo)
		o.logger.WithFields(logrus.Fields{
			"method":             "SigninHandler",
			"profile":            profile,
			"requested-redirect": redirectTo,
			"allowed-redirect":   config.AllowedRedirects[i],
			"is-allowed":         allowed,
		}).Debug("Can redirect?")
	}

	if !allowed {
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
		}).Error("Invalid redirect request")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Unacceptable redirect")
		return
	}

	cookie, err := r.Cookie(config.Name)
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
		"cookie":  cookie,
		"error":   err,
	}).Debug("Finding Cookie")

	if err == nil && cookie != nil {
		hashKey := []byte(config.CookieSecret)
		s := secureCookie.New(hashKey, nil)

		var token string
		err = s.Decode(config.Name, cookie.Value, &token)
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
			"cookie":  cookie,
			"token":   token,
			"error":   err,
		}).Debug("Decoded cookie value")

		if token != "" {
			err = config.verifyToken(token)
			if err == nil {
				if r.URL.Query().Get("rd") != "" {
					http.Redirect(w, r, r.URL.Query().Get("rd"), http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	state, err := o.stateStorer.SaveRedirectURIForClient(profile, redirectTo)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Unable to save auth request data and generate state token.")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Unable to save auth request data and generate state token.")
		return
	}

	o.logger.WithFields(logrus.Fields{
		"method":         "SigninHandler",
		"profile":        profile,
		"redirectBackTo": redirectTo,
		"stateToken":     state,
	}).Info("Authentication required - redirecting.")

	http.Redirect(w, r, config.oAuth2Config(fmt.Sprintf("%v/auth/callback", o.externalURL)).AuthCodeURL(state), http.StatusFound)
	return
}

var getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) {
	return config.oAuth2Config(fmt.Sprintf("%v/auth/callback", url)).Exchange(context.Background(), r.URL.Query().Get("code"))
}

var getIDToken = func(oauth2 *oauth2.Token) string {
	return oauth2.Extra("id_token").(string)
}

// CallbackHandler handles the return call from the oauth provider after authentication
func (o Oidc) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	profile, redirectURL, err := o.stateStorer.GetRedirectURI(state)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Error rehydrating state")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid state")
		return
	}

	o.logger.WithFields(logrus.Fields{
		"method":      "CallbackHandler",
		"profile":     profile,
		"state":       state,
		"redirectURL": redirectURL,
	}).Info("Callback received from oauth provider.")

	config, ok := o.clients[profile]
	if !ok {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
		}).Error("Profile not found in config.")

		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, http.StatusText(http.StatusForbidden))
		return
	}

	oauth2Token, err := getOAuth2Token(o.externalURL, r, config)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Failed to exchange token.")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to exchange token: %s", err.Error())
		return
	}

	rawIDToken := getIDToken(oauth2Token)
	err = config.verifyToken(rawIDToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to verify ID Token: %s", err.Error())
		return
	}

	hashKey := []byte(config.CookieSecret)
	s := secureCookie.New(hashKey, nil)
	encoded, err := s.Encode(config.Name, rawIDToken)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Error encoding cookie value.")
	}

	cookie := http.Cookie{
		Name:   config.Name,
		Path:   "/",
		Domain: config.CookieDomain,
		Value:  encoded,
	}
	http.SetCookie(w, &cookie)
	o.logger.WithFields(logrus.Fields{
		"method":  "CallbackHandler",
		"profile": profile,
		"cookie":  cookie,
	}).Debug("Cookie set - redirecting back to application.")

	if r.URL.Query().Get("rd") != "" {
		http.Redirect(w, r, r.URL.Query().Get("rd"), http.StatusFound)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return
}
