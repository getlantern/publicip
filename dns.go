package publicip

import (
	"context"
	"fmt"
	"net"
)

// DNSQueryType specifies what record type to query.
type DNSQueryType int

const (
	DNSTypeA   DNSQueryType = iota // A record lookup
	DNSTypeTXT                     // TXT record lookup
)

type dnsMethod struct {
	name       string // query hostname (e.g., "whoami.akamai.net")
	nameserver string // specific nameserver to use (e.g., "ns1-1.akamaitech.net:53")
	queryType  DNSQueryType
}

// NewDNS creates a DNS-based IP detection method that queries a special
// hostname on a specific nameserver that echoes back the querier's IP.
func NewDNS(name, nameserver string, queryType DNSQueryType) Method {
	return &dnsMethod{name: name, nameserver: nameserver, queryType: queryType}
}

func (d *dnsMethod) Name() string {
	return "dns:" + d.name
}

func (d *dnsMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "udp", d.nameserver)
		},
	}

	switch d.queryType {
	case DNSTypeA:
		addrs, err := resolver.LookupHost(ctx, d.name)
		if err != nil {
			return nil, nil, fmt.Errorf("dns %s: %w", d.name, err)
		}
		if len(addrs) == 0 {
			return nil, nil, fmt.Errorf("dns %s: no results", d.name)
		}
		ip := net.ParseIP(addrs[0])
		if ip == nil {
			return nil, nil, fmt.Errorf("dns %s: invalid IP %q", d.name, addrs[0])
		}
		return ip, nil, nil

	case DNSTypeTXT:
		txts, err := resolver.LookupTXT(ctx, d.name)
		if err != nil {
			return nil, nil, fmt.Errorf("dns %s TXT: %w", d.name, err)
		}
		if len(txts) == 0 {
			return nil, nil, fmt.Errorf("dns %s TXT: no results", d.name)
		}
		ip := net.ParseIP(txts[0])
		if ip == nil {
			return nil, nil, fmt.Errorf("dns %s TXT: invalid IP %q", d.name, txts[0])
		}
		return ip, nil, nil

	default:
		return nil, nil, fmt.Errorf("dns %s: unknown query type", d.name)
	}
}
