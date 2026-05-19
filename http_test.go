package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMethod_UsesSuppliedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.42"))
	}))
	t.Cleanup(srv.Close)

	calls := 0
	customClient := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return srv.Client().Transport.RoundTrip(r)
		}),
	}

	m := NewHTTPWithClient(srv.URL, FormatPlainText, customClient, "fronted")
	ip, _, err := m.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ip.String() != "203.0.113.42" {
		t.Errorf("ip = %s; want 203.0.113.42", ip)
	}
	if calls != 1 {
		t.Errorf("custom client called %d times; want 1", calls)
	}
	if name := m.Name(); name != "http[fronted]:"+srv.URL {
		t.Errorf("Name = %q; want labelled form", name)
	}
}

func TestHTTPMethod_DefaultClientWhenNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.7"))
	}))
	t.Cleanup(srv.Close)

	pkgCalls := 0
	originalTransport := httpClient.Transport
	httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		pkgCalls++
		return originalTransport.RoundTrip(r)
	})
	t.Cleanup(func() { httpClient.Transport = originalTransport })

	m := NewHTTP(srv.URL, FormatPlainText)
	ip, _, err := m.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ip.String() != "198.51.100.7" {
		t.Errorf("ip = %s; want 198.51.100.7", ip)
	}
	if pkgCalls != 1 {
		t.Errorf("package httpClient called %d times; want 1 (fallback path not exercised)", pkgCalls)
	}
	if name := m.Name(); name != "http:"+srv.URL {
		t.Errorf("Name = %q; want unlabelled form", name)
	}
}

func TestHTTPMethod_NilClientWithLabelDropsLabel(t *testing.T) {
	m := NewHTTPWithClient("https://example.com", FormatPlainText, nil, "fronted")
	if name := m.Name(); name != "http:https://example.com" {
		t.Errorf("Name = %q; want unlabelled form when client is nil", name)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
