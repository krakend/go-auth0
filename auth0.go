package auth0

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// SecretProvider will provide everything
// needed retrieve the secret.
type SecretProvider interface {
	GetSecret(r *http.Request) (interface{}, error)
}

// SecretProviderFunc simple wrappers to provide
// secret with functions.
type SecretProviderFunc func(*http.Request) (interface{}, error)

// GetSecret implements the SecretProvider interface.
func (f SecretProviderFunc) GetSecret(r *http.Request) (interface{}, error) {
	return f(r)
}

// NewKeyProvider provide a simple passphrase key provider.
func NewKeyProvider(key interface{}) SecretProvider {
	return SecretProviderFunc(func(_ *http.Request) (interface{}, error) {
		return key, nil
	})
}

var (
	// ErrNoJWTHeaders is returned when there are no headers in the JWT.
	ErrNoJWTHeaders = errors.New("No headers in the token")
	// ErrJWTFromTokenNotImplemented is returned when the secret provider cannot
	// obtain a .
	ErrJWTFromTokenNotImplemented = errors.New("Cannot extract JWT from Token: not implemented")
)

// TokenSecertProvider allows to extract the key ID from a JSONWebToken
// directly, and get the secret from it
type TokenSecretProvider interface {
	SecretFromToken(token *jwt.JSONWebToken) (interface{}, error)
}

type nopTokenSecretProvider struct{}

func (p *nopTokenSecretProvider) SecretFromToken(token *jwt.JSONWebToken) (interface{}, error) {
	return nil, ErrJWTFromTokenNotImplemented
}

// Configuration contains
// all the information about the
// Auth0 service.
type Configuration struct {
	secretProvider      SecretProvider
	expectedClaims      jwt.Expected
	signIn              jose.SignatureAlgorithm
	tokenSecretProvider TokenSecretProvider
}

// NewConfiguration creates a configuration for server
func NewConfiguration(provider SecretProvider, audience []string, issuer string, method jose.SignatureAlgorithm) Configuration {
	tokenSecretProvider, ok := provider.(TokenSecretProvider)
	if !ok {
		tokenSecretProvider = &nopTokenSecretProvider{}
	}
	return Configuration{
		secretProvider:      provider,
		expectedClaims:      jwt.Expected{Issuer: issuer, Audience: audience},
		signIn:              method,
		tokenSecretProvider: tokenSecretProvider,
	}
}

// NewConfigurationTrustProvider creates a configuration for server with no enforcement for token sig alg type, instead trust provider
func NewConfigurationTrustProvider(provider SecretProvider, audience []string, issuer string) Configuration {
	tokenSecretProvider, ok := provider.(TokenSecretProvider)
	if !ok {
		tokenSecretProvider = &nopTokenSecretProvider{}
	}
	return Configuration{
		secretProvider:      provider,
		expectedClaims:      jwt.Expected{Issuer: issuer, Audience: audience},
		tokenSecretProvider: tokenSecretProvider,
	}
}

// JWTValidator helps middleware
// to validate token
type JWTValidator struct {
	config    Configuration
	extractor RequestTokenExtractor
	leeway    time.Duration
}

// NewValidator creates a new
// validator with the provided configuration and the default leeway.
func NewValidator(config Configuration, extractor RequestTokenExtractor) *JWTValidator {
	return NewValidatorWithLeeway(config, extractor, time.Second)
}

// NewValidatorWithLeeway creates a new
// validator with the provided configuration.
func NewValidatorWithLeeway(config Configuration, extractor RequestTokenExtractor, leeway time.Duration) *JWTValidator {
	if extractor == nil {
		extractor = RequestTokenExtractorFunc(FromHeader)
	}
	if leeway < time.Second {
		leeway = time.Second
	}
	return &JWTValidator{
		config:    config,
		extractor: extractor,
		leeway:    leeway,
	}
}

func (v *JWTValidator) ValidateTokenHeaders(token *jwt.JSONWebToken) error {
	if len(token.Headers) < 1 {
		return ErrNoJWTHeaders
	}

	// trust secret provider when sig alg not configured and skip check
	if v.config.signIn != "" {
		header := token.Headers[0]
		if header.Algorithm != string(v.config.signIn) {
			return ErrInvalidAlgorithm
		}
	}
	return nil
}

// Validate validates a jwt.JSONWebToken
func (v *JWTValidator) ValidateTokenClaims(token *jwt.JSONWebToken, secretKey interface{}) (*jwt.JSONWebToken, error) {
	claims := jwt.Claims{}
	if err := token.Claims(secretKey, &claims); err != nil {
		return nil, err
	}

	expected := v.config.expectedClaims.WithTime(time.Now())
	err := claims.ValidateWithLeeway(expected, v.leeway)
	return token, err
}

// ValidateSigned validates a non parsed token in string form
func (v *JWTValidator) ValidateToken(token *jwt.JSONWebToken) (*jwt.JSONWebToken, error) {
	if err := v.ValidateTokenHeaders(token); err != nil {
		return nil, err
	}
	secretKey, err := v.config.tokenSecretProvider.SecretFromToken(token)
	if err != nil {
		return nil, err
	}
	return v.ValidateTokenClaims(token, secretKey)
}

// ValidateSigned validates a non parsed token in string form
func (v *JWTValidator) ValidateSigned(s string) (*jwt.JSONWebToken, error) {
	if s == "" {
		return nil, ErrTokenNotFound
	}
	token, err := jwt.ParseSigned(s)
	if err != nil {
		return nil, err
	}
	return v.ValidateToken(token)
}

// ValidateRequest validates the token within
// the http request.
func (v *JWTValidator) ValidateRequest(r *http.Request) (*jwt.JSONWebToken, error) {
	token, err := v.extractor.Extract(r)
	if err != nil {
		return nil, err
	}
	if err := v.ValidateTokenHeaders(token); err != nil {
		return nil, err
	}
	key, err := v.config.secretProvider.GetSecret(r)
	if err != nil {
		return nil, err
	}
	return v.ValidateTokenClaims(token, key)
}

// Claims unmarshall the claims of the provided token
func (v *JWTValidator) Claims(r *http.Request, token *jwt.JSONWebToken, values ...interface{}) error {
	key, err := v.config.secretProvider.GetSecret(r)
	if err != nil {
		return err
	}
	return token.Claims(key, values...)
}

// ClaimsFromToken unmarshall the claims of the provided token
func (v *JWTValidator) ClaimsFromToken(token *jwt.JSONWebToken, values ...interface{}) error {
	key, err := v.config.tokenSecretProvider.SecretFromToken(token)
	if err != nil {
		return err
	}
	return token.Claims(key, values...)
}
