package publicip

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockMethod is a test double that returns a configurable IP after a delay.
type mockMethod struct {
	name  string
	ip    net.IP
	geo   *GeoInfo
	err   error
	delay time.Duration
}

func (m *mockMethod) Name() string { return m.name }
func (m *mockMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	select {
	case <-time.After(m.delay):
		return m.ip, m.geo, m.err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func TestConsensus_AllAgree(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 2,
		Methods: []Method{
			&mockMethod{name: "a", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "b", ip: ip, delay: 20 * time.Millisecond},
			&mockMethod{name: "c", ip: ip, delay: 30 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IP.Equal(ip) {
		t.Errorf("expected %s, got %s", ip, result.IP)
	}
	if result.Confidence < 0.66 {
		t.Errorf("expected high confidence, got %.2f", result.Confidence)
	}
}

func TestConsensus_MajorityWins(t *testing.T) {
	correct := net.ParseIP("203.0.113.1")
	wrong := net.ParseIP("198.51.100.1")
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 2,
		Methods: []Method{
			&mockMethod{name: "a", ip: correct, delay: 10 * time.Millisecond},
			&mockMethod{name: "b", ip: wrong, delay: 20 * time.Millisecond},
			&mockMethod{name: "c", ip: correct, delay: 30 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IP.Equal(correct) {
		t.Errorf("expected majority IP %s, got %s", correct, result.IP)
	}
	if len(result.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(result.Sources))
	}
}

func TestConsensus_EarlyReturn(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	cfg := &Config{
		Timeout:      5 * time.Second,
		MinConsensus: 2,
		Methods: []Method{
			&mockMethod{name: "fast1", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "fast2", ip: ip, delay: 20 * time.Millisecond},
			&mockMethod{name: "slow", ip: ip, delay: 3 * time.Second},
		},
	}

	start := time.Now()
	result, err := Detect(context.Background(), cfg)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	if !result.IP.Equal(ip) {
		t.Errorf("expected %s, got %s", ip, result.IP)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected early return, took %v", elapsed)
	}
}

func TestConsensus_AllFail(t *testing.T) {
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 1,
		Methods: []Method{
			&mockMethod{name: "a", err: fmt.Errorf("fail"), delay: 10 * time.Millisecond},
			&mockMethod{name: "b", err: fmt.Errorf("fail"), delay: 10 * time.Millisecond},
		},
	}

	_, err := Detect(context.Background(), cfg)
	if err == nil {
		t.Error("expected error when all methods fail")
	}
}

func TestConsensus_Timeout(t *testing.T) {
	cfg := &Config{
		Timeout:      100 * time.Millisecond,
		MinConsensus: 2,
		Methods: []Method{
			&mockMethod{name: "slow1", ip: net.ParseIP("1.1.1.1"), delay: 5 * time.Second},
			&mockMethod{name: "slow2", ip: net.ParseIP("1.1.1.1"), delay: 5 * time.Second},
		},
	}

	_, err := Detect(context.Background(), cfg)
	if err == nil {
		t.Error("expected error on timeout")
	}
}

func TestConsensus_OneFastOneSlow(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 1,
		Methods: []Method{
			&mockMethod{name: "fast", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "slow", ip: ip, delay: 5 * time.Second},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IP.Equal(ip) {
		t.Errorf("expected %s, got %s", ip, result.IP)
	}
}

func TestConsensus_GeoInfoPreserved(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	geo := &GeoInfo{Country: "US", City: "Denver", Org: "Comcast"}
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 2, // wait for both so geo is captured
		Methods: []Method{
			&mockMethod{name: "plain", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "geo", ip: ip, geo: geo, delay: 20 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Geo == nil {
		t.Fatal("expected geo info")
	}
	if result.Geo.Country != "US" {
		t.Errorf("expected country US, got %s", result.Geo.Country)
	}
}

func TestConsensus_CGNATDetected(t *testing.T) {
	publicIP := net.ParseIP("203.0.113.1")
	gatewayIP := net.ParseIP("100.64.0.1") // CGNAT range
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 3, // wait for all so UPnP result is captured
		Methods: []Method{
			&mockMethod{name: "stun:server", ip: publicIP, delay: 10 * time.Millisecond},
			&mockMethod{name: "http:service", ip: publicIP, delay: 15 * time.Millisecond},
			&mockMethod{name: "upnp", ip: gatewayIP, delay: 20 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsCGNAT {
		t.Error("expected CGNAT to be detected")
	}
	if !result.IP.Equal(publicIP) {
		t.Errorf("expected public IP %s (not gateway), got %s", publicIP, result.IP)
	}
}

func TestConsensus_NoCGNATWhenSameIP(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 1,
		Methods: []Method{
			&mockMethod{name: "stun:server", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "upnp", ip: ip, delay: 20 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsCGNAT {
		t.Error("CGNAT should not be flagged when UPnP and STUN agree")
	}
}

func TestConsensus_NilMethodsUsesDefaults(t *testing.T) {
	cfg := &Config{
		Timeout:      100 * time.Millisecond,
		MinConsensus: 100, // unreachable, will timeout
	}
	// Just verify it doesn't panic — will timeout since real servers may not respond in 100ms
	Detect(context.Background(), cfg)
}

func TestConsensus_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	cfg := &Config{
		Timeout:      time.Second,
		MinConsensus: 2,
		Methods: []Method{
			&mockMethod{name: "a", ip: ip, delay: 10 * time.Millisecond},
			&mockMethod{name: "b", ip: ip, delay: 20 * time.Millisecond},
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IP.Equal(ip) {
		t.Errorf("expected IPv6 %s, got %s", ip, result.IP)
	}
}

// ── STUN parser unit tests ──

func TestParseXORMappedAddress_IPv4(t *testing.T) {
	var txID [12]byte
	// XOR 192.0.2.1 (0xC0000201) with magic cookie 0x2112A442
	// Result: 0xC0000201 ^ 0x2112A442 = 0xE112A643
	val := []byte{
		0x00, 0x01, // family: IPv4
		0x00, 0x00, // port (don't care)
		0xE1, 0x12, 0xA6, 0x43, // XORed address
	}
	ip := parseXORMappedAddress(val, txID)
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	expected := net.ParseIP("192.0.2.1").To4()
	if !ip.Equal(expected) {
		t.Errorf("expected %s, got %s", expected, ip)
	}
}

func TestParseMappedAddress_IPv4(t *testing.T) {
	val := []byte{
		0x00, 0x01, // family: IPv4
		0x00, 0x00, // port
		192, 0, 2, 1, // address
	}
	ip := parseMappedAddress(val)
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if !ip.Equal(net.ParseIP("192.0.2.1").To4()) {
		t.Errorf("expected 192.0.2.1, got %s", ip)
	}
}

func TestParseMappedAddress_TooShort(t *testing.T) {
	val := []byte{0x00, 0x01, 0x00}
	ip := parseMappedAddress(val)
	if ip != nil {
		t.Errorf("expected nil for short input, got %s", ip)
	}
}

func TestParseSTUNAttributes_PreferXORMapped(t *testing.T) {
	var txID [12]byte
	// Build attributes with both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS
	// XOR-MAPPED-ADDRESS should be preferred (it comes first in real responses)
	xorAttr := []byte{
		0x00, 0x20, // type: XOR-MAPPED-ADDRESS
		0x00, 0x08, // length: 8
		0x00, 0x01, // family: IPv4
		0x00, 0x00, // port
		0xE1, 0x12, 0xA6, 0x43, // XORed 192.0.2.1
	}
	mappedAttr := []byte{
		0x00, 0x01, // type: MAPPED-ADDRESS
		0x00, 0x08, // length: 8
		0x00, 0x01, // family: IPv4
		0x00, 0x00, // port
		10, 0, 0, 1, // 10.0.0.1 (wrong, should not be used)
	}
	attrs := append(xorAttr, mappedAttr...)
	ip := parseSTUNAttributes(attrs, txID)
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if !ip.Equal(net.ParseIP("192.0.2.1").To4()) {
		t.Errorf("expected 192.0.2.1, got %s", ip)
	}
}

// ── Integration tests (require network) ──

func TestIntegration_FullDetect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := Detect(ctx, nil)
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

	t.Logf("IP: %s (confidence %.0f%%, sources: %v)", result.IP, result.Confidence*100, result.Sources)
	for _, r := range result.All {
		t.Logf("  %s: %s (%dms)", r.Source, r.IP, r.Latency.Milliseconds())
	}
}

func TestIntegration_STUNOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := &Config{
		Timeout:      5 * time.Second,
		MinConsensus: 1,
		Methods: []Method{
			NewSTUN("stun.cloudflare.com:3478"),
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("STUN-only detect failed: %v", err)
	}
	t.Logf("STUN: %s (%dms)", result.IP, result.All[0].Latency.Milliseconds())
}

func TestIntegration_DNSOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := &Config{
		Timeout:      5 * time.Second,
		MinConsensus: 1,
		Methods: []Method{
			NewDNS("myip.opendns.com", "resolver1.opendns.com:53", DNSTypeA),
		},
	}

	result, err := Detect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DNS-only detect failed: %v", err)
	}
	t.Logf("DNS: %s (%dms)", result.IP, result.All[0].Latency.Milliseconds())
}
