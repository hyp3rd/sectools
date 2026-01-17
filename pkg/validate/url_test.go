package validate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeRoundTripper struct {
	responses map[string]*http.Response
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if resp, ok := f.responses[req.URL.String()]; ok {
		return resp, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

func TestURLValidateBasic(t *testing.T) {
	t.Parallel()

	validator, err := NewURLValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "https://example.com/path")
	if err != nil {
		t.Fatalf("expected valid url, got %v", err)
	}
}

func TestURLRejectUserInfo(t *testing.T) {
	t.Parallel()

	validator, err := NewURLValidator()
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "https://user:pass@example.com")
	if !errors.Is(err, ErrURLUserInfoNotAllowed) {
		t.Fatalf("expected ErrURLUserInfoNotAllowed, got %v", err)
	}
}

func TestURLRejectPrivateIP(t *testing.T) {
	t.Parallel()

	validator, err := NewURLValidator(
		WithURLAllowIPLiteral(true),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "https://127.0.0.1")
	if !errors.Is(err, ErrURLPrivateIPNotAllowed) {
		t.Fatalf("expected ErrURLPrivateIPNotAllowed, got %v", err)
	}
}

func TestURLRedirectCheck(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: &fakeRoundTripper{
			responses: map[string]*http.Response{
				"https://example.com/start": {
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"/final"}},
					Body:       io.NopCloser(strings.NewReader("")),
				},
				"https://example.com/final": {
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				},
			},
		},
	}

	validator, err := NewURLValidator(
		WithURLCheckRedirects(3),
		WithURLHTTPClient(client),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	result, err := validator.Validate(context.Background(), "https://example.com/start")
	if err != nil {
		t.Fatalf("expected valid url, got %v", err)
	}

	if len(result.Redirects) != 1 {
		t.Fatalf("expected 1 redirect, got %d", len(result.Redirects))
	}
}

func TestURLRedirectLoop(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: &fakeRoundTripper{
			responses: map[string]*http.Response{
				"https://example.com/loop": {
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"/loop"}},
					Body:       io.NopCloser(strings.NewReader("")),
				},
			},
		},
	}

	validator, err := NewURLValidator(
		WithURLCheckRedirects(2),
		WithURLHTTPClient(client),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "https://example.com/loop")
	if !errors.Is(err, ErrURLRedirectLoop) {
		t.Fatalf("expected ErrURLRedirectLoop, got %v", err)
	}
}

func TestURLReputationBlock(t *testing.T) {
	t.Parallel()

	checker := NewStaticReputation(nil, []string{"example.com"})

	validator, err := NewURLValidator(
		WithURLReputationChecker(checker),
	)
	if err != nil {
		t.Fatalf("expected validator, got %v", err)
	}

	_, err = validator.Validate(context.Background(), "https://example.com")
	if !errors.Is(err, ErrURLReputationBlocked) {
		t.Fatalf("expected ErrURLReputationBlocked, got %v", err)
	}
}

func TestURLRejectHTTPWithSchemesOption(t *testing.T) {
	t.Parallel()

	_, err := NewURLValidator(WithURLAllowedSchemes("http"))
	if !errors.Is(err, ErrInvalidURLConfig) {
		t.Fatalf("expected ErrInvalidURLConfig, got %v", err)
	}
}
