// Package publicip determines the caller's public IP address using multiple
// redundant techniques (STUN, HTTP, DNS, UPnP) and returns a consensus result.
package publicip

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result holds a single IP detection result from one method.
type Result struct {
	IP      net.IP
	Source  string
	Latency time.Duration
	Geo     *GeoInfo
}

// GeoInfo holds optional geographic information about the detected IP.
type GeoInfo struct {
	Country string
	City    string
	ASN     string
	Org     string
}

// DetectResult is the consensus result from multiple methods.
type DetectResult struct {
	IP         net.IP
	Confidence float64   // 0.0-1.0, based on method agreement
	Sources    []string  // which methods agreed on this IP
	Geo        *GeoInfo  // geo info if any method provided it
	All        []Result  // all individual results
	IsCGNAT    bool      // true if UPnP returned a different IP than internet-facing methods
}

// Config controls which methods to use and their behavior.
type Config struct {
	Timeout      time.Duration // per-method timeout (default 5s)
	MinConsensus int           // return early once this many methods agree (default 2)
	Methods      []Method      // methods to use; nil = all defaults
}

var defaultConfig = Config{
	Timeout:      5 * time.Second,
	MinConsensus: 2,
}

// Detect races all configured methods in parallel and returns the consensus
// public IP. It returns early once MinConsensus methods agree on the same IP.
func Detect(ctx context.Context, cfg *Config) (*DetectResult, error) {
	if cfg == nil {
		cfg = &defaultConfig
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MinConsensus == 0 {
		cfg.MinConsensus = 2
	}

	methods := cfg.Methods
	if len(methods) == 0 {
		methods = DefaultMethods()
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	var mu sync.Mutex
	results := make([]Result, 0, len(methods))
	votes := make(map[string][]string) // ip string → source names

	// Channel to signal early consensus
	done := make(chan struct{}, 1)

	var wg sync.WaitGroup
	for _, m := range methods {
		wg.Add(1)
		go func(m Method) {
			defer wg.Done()
			start := time.Now()
			ip, geo, err := m.Detect(ctx)
			if err != nil || ip == nil {
				return
			}

			r := Result{
				IP:      ip,
				Source:  m.Name(),
				Latency: time.Since(start),
				Geo:     geo,
			}

			mu.Lock()
			results = append(results, r)
			ipStr := ip.String()
			votes[ipStr] = append(votes[ipStr], m.Name())
			// Check for early consensus
			if len(votes[ipStr]) >= cfg.MinConsensus {
				select {
				case done <- struct{}{}:
				default:
				}
			}
			mu.Unlock()
		}(m)
	}

	// Wait for either consensus, all methods done, or timeout
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case <-done:
		cancel() // Stop remaining methods to save resources
	case <-allDone:
	case <-ctx.Done():
	}

	mu.Lock()
	defer mu.Unlock()

	if len(results) == 0 {
		return nil, fmt.Errorf("no methods returned a result")
	}

	return buildConsensus(results, votes), nil
}

func buildConsensus(results []Result, votes map[string][]string) *DetectResult {
	// Find the IP with the most votes
	var bestIP string
	var bestCount int
	for ip, sources := range votes {
		if len(sources) > bestCount {
			bestIP = ip
			bestCount = len(sources)
		}
	}

	// Sort sources for deterministic output
	sources := votes[bestIP]
	sort.Strings(sources)

	// Find geo info from any result that provided it
	var geo *GeoInfo
	for _, r := range results {
		if r.IP.String() == bestIP && r.Geo != nil {
			geo = r.Geo
			break
		}
	}

	// Detect CGNAT: if a local/gateway method returned a different IP
	isCGNAT := false
	for _, r := range results {
		if r.Source == "upnp" && r.IP.String() != bestIP {
			isCGNAT = true
			break
		}
	}

	confidence := float64(bestCount) / float64(len(results))
	if confidence > 1 {
		confidence = 1
	}

	return &DetectResult{
		IP:         net.ParseIP(bestIP),
		Confidence: confidence,
		Sources:    sources,
		Geo:        geo,
		All:        results,
		IsCGNAT:    isCGNAT,
	}
}
