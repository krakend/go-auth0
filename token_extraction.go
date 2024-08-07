package auth0

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
)

var (
	// ErrTokenNotFound is returned by the ValidateRequest if the token was not
	// found in the request.
	ErrTokenNotFound = errors.New("Token not found")
)

// RequestTokenExtractor can extract a JWT
// from a request.
type RequestTokenExtractor interface {
	Extract(r *http.Request) (*jwt.JSONWebToken, error)
}

// RequestTokenExtractorFunc function conforming
// to the RequestTokenExtractor interface.
type RequestTokenExtractorFunc func(r *http.Request) (*jwt.JSONWebToken, error)

// Extract calls f(r)
func (f RequestTokenExtractorFunc) Extract(r *http.Request) (*jwt.JSONWebToken, error) {
	return f(r)
}

// FromMultiple combines multiple extractors by chaining.
func FromMultiple(extractors ...RequestTokenExtractor) RequestTokenExtractor {
	return RequestTokenExtractorFunc(func(r *http.Request) (*jwt.JSONWebToken, error) {
		for _, e := range extractors {
			token, err := e.Extract(r)
			if err == ErrTokenNotFound {
				continue
			} else if err != nil {
				return nil, err
			}
			return token, nil
		}
		return nil, ErrTokenNotFound
	})
}

// FromHeader looks for the request in the
// authentication header or call ParseMultipartForm
// if not present.
// TODO: Implement parsing form data.
func FromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	raw := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[0:7], "BEARER ") {
		raw = h[7:]
	}
	if raw == "" {
		return nil, ErrTokenNotFound
	}
	return jwt.ParseSigned(raw)
}

// FromParams returns the JWT when passed as the URL query param "token".
func FromParams(r *http.Request) (*jwt.JSONWebToken, error) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		return nil, ErrTokenNotFound
	}
	return jwt.ParseSigned(raw)
}
