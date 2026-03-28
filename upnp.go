package publicip

import (
	"context"
	"fmt"
	"net"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

type upnpMethod struct{}

// NewUPnP creates a UPnP-based IP detection method that queries the local
// gateway for its external IP address. This only works when the gateway
// supports UPnP IGD and has it enabled. Returns the gateway's external IP,
// which may differ from the internet-facing IP if behind CGNAT.
func NewUPnP() Method {
	return &upnpMethod{}
}

func (u *upnpMethod) Name() string {
	return "upnp"
}

func (u *upnpMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	// Try IGDv2 first, then fall back to IGDv1
	ip, err := u.detectIGD2(ctx)
	if err == nil {
		return ip, nil, nil
	}
	ip, err = u.detectIGD1(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("upnp: no gateway found: %w", err)
	}
	return ip, nil, nil
}

func (u *upnpMethod) detectIGD2(ctx context.Context) (net.IP, error) {
	clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv2 clients")
	}
	ipStr, err := clients[0].GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP from IGDv2: %q", ipStr)
	}
	return ip, nil
}

func (u *upnpMethod) detectIGD1(ctx context.Context) (net.IP, error) {
	clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv1 clients")
	}
	ipStr, err := clients[0].GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP from IGDv1: %q", ipStr)
	}
	return ip, nil
}
