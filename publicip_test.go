package publicip_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/getlantern/publicip"
)

func TestDetect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := publicip.Detect(ctx, nil)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.IP == nil {
		t.Fatal("expected non-nil IP")
	}

	if result.IP.IsLoopback() || result.IP.IsPrivate() {
		t.Errorf("expected public IP, got %s", result.IP)
	}

	if result.Confidence <= 0 {
		t.Errorf("expected positive confidence, got %f", result.Confidence)
	}

	if len(result.Sources) == 0 {
		t.Error("expected at least one source")
	}

	t.Logf("IP: %s (confidence %.0f%%, sources: %v)", result.IP, result.Confidence*100, result.Sources)
	for _, r := range result.All {
		t.Logf("  %s: %s (%dms)", r.Source, r.IP, r.Latency.Milliseconds())
	}
}

func TestDetect_CustomMethods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use only HTTP methods
	cfg := &publicip.Config{
		Timeout:      10 * time.Second,
		MinConsensus: 2,
		Methods: []publicip.Method{
			publicip.NewHTTP("https://icanhazip.com", publicip.FormatPlainText),
			publicip.NewHTTP("https://checkip.amazonaws.com", publicip.FormatPlainText),
			publicip.NewHTTP("https://ipinfo.io/json", publicip.FormatIPInfoJSON),
		},
	}

	result, err := publicip.Detect(ctx, cfg)
	if err != nil {
		t.Fatalf("Detect with custom methods failed: %v", err)
	}

	if result.IP == nil {
		t.Fatal("expected non-nil IP")
	}

	t.Logf("HTTP-only: %s (confidence %.0f%%, sources: %v)", result.IP, result.Confidence*100, result.Sources)
}

func TestDetect_SingleMethod(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &publicip.Config{
		Timeout:      5 * time.Second,
		MinConsensus: 1,
		Methods: []publicip.Method{
			publicip.NewHTTP("https://icanhazip.com", publicip.FormatPlainText),
		},
	}

	result, err := publicip.Detect(ctx, cfg)
	if err != nil {
		t.Fatalf("Detect single method failed: %v", err)
	}

	if result.IP == nil {
		t.Fatal("expected non-nil IP")
	}

	ip := net.ParseIP(result.IP.String())
	if ip == nil {
		t.Fatalf("result IP is not parseable: %s", result.IP)
	}

	t.Logf("Single method: %s", result.IP)
}
