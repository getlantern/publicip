# publicip

Determine your public IP address with high confidence, even in hostile network environments.

`publicip` races multiple independent detection techniques in parallel — STUN, HTTP, DNS, and UPnP — and uses consensus voting to return the IP that the most methods agree on. If any individual service is blocked, rate-limited, or lying, the others outvote it.

```go
result, err := publicip.Detect(ctx, nil)
fmt.Println(result.IP)         // 203.0.113.42
fmt.Println(result.Confidence) // 1.0 (all methods agree)
fmt.Println(result.Sources)    // [stun:stun.cloudflare.com:3478 dns:myip.opendns.com http:https://icanhazip.com]
```

## Why this exists

Knowing your own public IP is simple on an open network. It's hard when:

- **You're behind a national firewall** that blocks popular services (China blocks `api.ipify.org`, Google STUN servers, and many more)
- **You're in a sanctioned country** where AWS, Google, and Cloudflare services are geo-blocked (Iran, Cuba)
- **Your ISP hijacks DNS** and returns wrong answers for IP-echo services
- **You're behind carrier-grade NAT** and need to know whether your "public" IP is actually shared
- **You're on a low-power mobile device** and can't afford to wait 10 seconds for HTTP timeouts

This library was built for [Lantern](https://lantern.io), a censorship circumvention tool used by millions in China, Iran, and Russia. It needs to reliably detect client IPs on networks that are actively hostile to this kind of detection.

## How it works

```
                    ┌─── STUN (Cloudflare) ──→ UDP ──→ 203.0.113.42
                    ├─── STUN (Nextcloud)  ──→ UDP ──→ 203.0.113.42
   Detect() ────────├─── HTTP (icanhazip)  ──→ TLS ──→ 203.0.113.42   ──→  Consensus: 203.0.113.42
     (parallel)     ├─── HTTP (ipinfo.io)  ──→ TLS ──→ 203.0.113.42        Confidence: 100%
                    ├─── DNS  (Akamai)     ──→ UDP ──→ 203.0.113.42        Sources: 5/7
                    ├─── DNS  (OpenDNS)    ──→ UDP ──→ 203.0.113.42
                    └─── UPnP (gateway)    ──→ LAN ──→ 10.0.0.1  (← CGNAT detected)
```

1. All methods launch concurrently
2. Each returns as fast as it can (STUN/DNS: ~25ms, HTTP: ~200ms)
3. As soon as `MinConsensus` methods agree (default: 2), the result is returned immediately
4. Remaining in-flight methods are cancelled to save battery and bandwidth
5. If the UPnP gateway returns a different IP, CGNAT is flagged

## Censorship-resistant by default

The default method set avoids services known to be blocked in major censored regions:

Method | Service | China | Iran | Russia | Protocol
-------|---------|:-----:|:----:|:------:|---------
STUN | `stun.cloudflare.com` | ✅ | ✅ | ⚠️ | UDP 3478
STUN | `stun.nextcloud.com` | ✅ | ✅ | ✅ | UDP 3478
HTTP | `icanhazip.com` | ✅ | ⚠️ | ⚠️ | HTTPS
HTTP | `ipinfo.io` | ✅ | ❓ | ❓ | HTTPS
HTTP | `checkip.amazonaws.com` | ✅ | ❌ | ✅ | HTTPS
DNS | `whoami.akamai.net` | ✅ | ✅ | ✅ | UDP 53
DNS | `myip.opendns.com` | ✅ | ❌ | ✅ | UDP 53
UPnP | Local gateway | ✅ | ✅ | ✅ | LAN

**No Google services** are used by default — Google STUN and DNS are blocked in China.

Even if half the methods are blocked, the remaining ones provide enough signal for a confident result.

## Optimized for mobile

Built for low-power Android devices on constrained networks:

- **Zero-copy STUN** — Implements RFC 5389 with stack-allocated buffers (128 bytes), no heap allocations in the hot path
- **No heavy dependencies** — Raw UDP for STUN instead of pulling in `pion/stun` and its 20+ transitive deps. Only external dep is `goupnp` for UPnP
- **Fast random** — Uses `math/rand` for STUN transaction IDs (not security-sensitive) instead of slow `crypto/rand` which blocks on Android's entropy pool
- **Connection-less HTTP** — Disables keep-alive to free sockets immediately after each response
- **Early cancellation** — Once consensus is reached, remaining goroutines are cancelled via context, stopping in-flight DNS lookups, STUN packets, and HTTP requests
- **Typical latency: 25-200ms** — STUN and DNS resolve in ~25ms; consensus reached before HTTP methods even respond

## Installation

```
go get github.com/getlantern/publicip
```

## Usage

### Basic detection

```go
ctx := context.Background()
result, err := publicip.Detect(ctx, nil) // nil = use defaults
if err != nil {
    log.Fatal(err)
}
fmt.Printf("IP: %s (confidence: %.0f%%)\n", result.IP, result.Confidence*100)
```

### With geo info

```go
result, _ := publicip.Detect(ctx, nil)
if result.Geo != nil {
    fmt.Printf("Country: %s, City: %s, Org: %s\n",
        result.Geo.Country, result.Geo.City, result.Geo.Org)
}
```

### Custom methods

```go
cfg := &publicip.Config{
    Timeout:      3 * time.Second,
    MinConsensus: 1,
    Methods: []publicip.Method{
        publicip.NewSTUN("stun.cloudflare.com:3478"),
        publicip.NewHTTP("https://icanhazip.com", publicip.FormatPlainText),
    },
}
result, err := publicip.Detect(ctx, cfg)
```

### CGNAT detection

```go
result, _ := publicip.Detect(ctx, nil)
if result.IsCGNAT {
    fmt.Println("Behind carrier-grade NAT — gateway IP differs from public IP")
}
```

### Add your own method

```go
type myMethod struct{}

func (m *myMethod) Name() string { return "custom:myservice" }
func (m *myMethod) Detect(ctx context.Context) (net.IP, *publicip.GeoInfo, error) {
    // Your detection logic here
    return net.ParseIP("1.2.3.4"), nil, nil
}
```

## CLI

```bash
go run github.com/getlantern/publicip/cmd/publicip@latest
```

```
Detecting public IP using multiple methods...

Public IP:   97.118.61.33
Confidence:  100% (2/2 methods agree)
Sources:     [dns:myip.opendns.com stun:stun.cloudflare.com:3478]

All results:
  stun:stun.cloudflare.com:3478        97.118.61.33  (24ms)
  dns:myip.opendns.com                 97.118.61.33  (33ms)
```

## Detection methods

### STUN (Session Traversal Utilities for NAT)

Sends a single UDP packet to a STUN server. The server reflects back your public IP as it sees it. Implements bare-minimum RFC 5389 with no external dependencies — just 150 lines of Go reading raw UDP.

**Pros:** Fastest method (~25ms). Works behind all NAT types. Uses UDP so it's hard to DPI-block without collateral damage.
**Cons:** Requires the STUN server to be reachable on UDP port 3478.

### HTTP

HTTPS GET to a service that returns your IP. `icanhazip.com` returns plain text; `ipinfo.io` returns JSON with country, city, and ISP.

**Pros:** Most reliable in unblocked environments. Some services return geo data.
**Cons:** Slowest method (~200-500ms). TLS handshake is expensive on slow connections. Services can be individually blocked.

### DNS

Queries a special hostname on a specific nameserver that echoes back the querier's IP address. Uses Go's built-in resolver with a custom dial function to target specific nameservers.

**Pros:** Fast (~30ms). Uses UDP port 53 which is rarely blocked. Different infrastructure than HTTP.
**Cons:** Some ISPs hijack DNS responses.

### UPnP

Queries the local network gateway (router) for its external IP via UPnP IGD protocol. This is the only method that works entirely on the LAN.

**Pros:** No internet access needed. Detects CGNAT (if gateway IP differs from STUN/HTTP results, you're behind CGNAT).
**Cons:** Many routers disable UPnP. Doesn't work behind CGNAT. Slowest due to SSDP discovery.

## License

Apache 2.0
