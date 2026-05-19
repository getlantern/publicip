package publicip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Shared HTTP client — no keep-alive (saves sockets on Android),
// short TLS handshake timeout, small response limit.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 4 * time.Second,
		MaxIdleConns:        0,
	},
}

// ResponseFormat specifies how to parse the HTTP response.
type ResponseFormat int

const (
	FormatPlainText  ResponseFormat = iota // response body is just the IP
	FormatIPInfoJSON                       // ipinfo.io-style JSON: {"ip":"...","country":"...","org":"..."}
)

type httpMethod struct {
	url    string
	format ResponseFormat
	// client overrides the package-default httpClient. nil = use the
	// shared direct client. Set via NewHTTPWithClient when the caller
	// wants to route detection through a domain-fronted (or otherwise
	// custom) transport to survive endpoint-level blocking.
	client *http.Client
	// label is appended to Name() so multiple methods using the same
	// URL through different clients show distinct sources in
	// consensus results.
	label string
}

// NewHTTP creates an HTTP-based IP detection method using the package's
// direct HTTP client. Suitable for unrestricted networks where the
// detection endpoint is directly reachable.
func NewHTTP(url string, format ResponseFormat) Method {
	return &httpMethod{url: url, format: format}
}

// NewHTTPWithClient creates an HTTP-based IP detection method that uses
// the supplied *http.Client for the request. Intended for callers that
// want the detection to ride a non-default transport (e.g. radiance's
// kindling-fronted client) so the request survives endpoint blocking
// without changing which IP gets reported — the CDN/proxy doesn't
// rewrite the source IP, so the response is still the user's real IP.
//
// label distinguishes this method from a direct one targeting the same
// URL in consensus output (e.g. "fronted").
func NewHTTPWithClient(url string, format ResponseFormat, client *http.Client, label string) Method {
	return &httpMethod{url: url, format: format, client: client, label: label}
}

func (h *httpMethod) Name() string {
	if h.label != "" {
		return "http[" + h.label + "]:" + h.url
	}
	return "http:" + h.url
}

func (h *httpMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", h.url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "publicip/1.0")

	c := h.client
	if c == nil {
		c = httpClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http %s: %w", h.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("http %s: status %d", h.url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, nil, fmt.Errorf("http %s: read: %w", h.url, err)
	}

	switch h.format {
	case FormatPlainText:
		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, nil, fmt.Errorf("http %s: invalid IP %q", h.url, ipStr)
		}
		return ip, nil, nil

	case FormatIPInfoJSON:
		return parseIPInfoJSON(body, h.url)

	default:
		return nil, nil, fmt.Errorf("http %s: unknown format", h.url)
	}
}

func parseIPInfoJSON(body []byte, url string) (net.IP, *GeoInfo, error) {
	var resp struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		City    string `json:"city"`
		Org     string `json:"org"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, fmt.Errorf("http %s: json: %w", url, err)
	}
	ip := net.ParseIP(resp.IP)
	if ip == nil {
		return nil, nil, fmt.Errorf("http %s: invalid IP %q", url, resp.IP)
	}
	var geo *GeoInfo
	if resp.Country != "" || resp.City != "" || resp.Org != "" {
		geo = &GeoInfo{
			Country: resp.Country,
			City:    resp.City,
			Org:     resp.Org,
		}
	}
	return ip, geo, nil
}
