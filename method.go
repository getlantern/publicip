package publicip

import (
	"context"
	"net"
)

// Method is a single IP detection technique.
type Method interface {
	Name() string
	Detect(ctx context.Context) (net.IP, *GeoInfo, error)
}

// DefaultMethods returns the default set of detection methods, ordered by
// expected reliability and speed. Methods are run in parallel, not sequentially.
func DefaultMethods() []Method {
	return []Method{
		// STUN — fast UDP, works behind most NATs, no HTTP needed
		NewSTUN("stun.cloudflare.com:3478"),
		NewSTUN("stun.nextcloud.com:3478"),

		// HTTP — reliable in most environments, some return geo data
		NewHTTP("https://icanhazip.com", FormatPlainText),
		NewHTTP("https://ipinfo.io/json", FormatIPInfoJSON),
		NewHTTP("https://checkip.amazonaws.com", FormatPlainText),

		// DNS — fast, different infrastructure than HTTP
		NewDNS("whoami.akamai.net", "ns1-1.akamaitech.net:53", DNSTypeA),
		NewDNS("myip.opendns.com", "resolver1.opendns.com:53", DNSTypeA),

		// UPnP — local network, detects CGNAT
		NewUPnP(),
	}
}
