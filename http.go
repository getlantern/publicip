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
}

// NewHTTP creates an HTTP-based IP detection method.
func NewHTTP(url string, format ResponseFormat) Method {
	return &httpMethod{url: url, format: format}
}

func (h *httpMethod) Name() string {
	return "http:" + h.url
}

func (h *httpMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", h.url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "publicip/1.0")

	resp, err := httpClient.Do(req)
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
