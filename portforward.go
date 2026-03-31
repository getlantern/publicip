package publicip

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

// ErrNoPortForwarding is returned when no port forwarding method (UPnP, NAT-PMP)
// is available on the network.
var ErrNoPortForwarding = errors.New("no port forwarding method available")

// PortMapping holds the details of an active port mapping.
type PortMapping struct {
	ExternalPort  uint16
	InternalPort  uint16
	InternalIP    string
	Protocol      string // "TCP" or "UDP"
	LeaseDuration time.Duration
	Method        string // "upnp-igd2", "upnp-igd1", "natpmp"
}

// PortForwarder manages port mappings on the local gateway via UPnP IGD or NAT-PMP.
type PortForwarder struct {
	mu      sync.Mutex
	mapping *PortMapping
	stopC   chan struct{}

	// igdClient is the UPnP client used for the active mapping (either IGDv2 or v1).
	// Only one of these will be set based on which version the gateway supports.
	igd2Client *internetgateway2.WANIPConnection2
	igd1Client *internetgateway2.WANIPConnection1
}

// NewPortForwarder creates a PortForwarder by discovering the local gateway.
// It does NOT create a mapping — call MapPort for that.
func NewPortForwarder() *PortForwarder {
	return &PortForwarder{}
}

// MapPort opens a port on the gateway, forwarding external traffic to the given
// internal port on this machine. It tries UPnP IGDv2, then IGDv1. If the
// requested external port is taken, it retries with random ports up to maxRetries times.
//
// The description appears in the router's port mapping table.
func (pf *PortForwarder) MapPort(ctx context.Context, internalPort uint16, description string) (*PortMapping, error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.mapping != nil {
		return pf.mapping, nil // already mapped
	}

	localIP, err := localIPForGateway()
	if err != nil {
		return nil, fmt.Errorf("determine local IP: %w", err)
	}

	// Try IGDv2 first
	mapping, err := pf.tryIGD2(ctx, localIP, internalPort, description)
	if err == nil {
		pf.mapping = mapping
		return mapping, nil
	}

	// Fall back to IGDv1
	mapping, err = pf.tryIGD1(ctx, localIP, internalPort, description)
	if err == nil {
		pf.mapping = mapping
		return mapping, nil
	}

	return nil, fmt.Errorf("%w: UPnP failed: %v", ErrNoPortForwarding, err)
}

// UnmapPort removes the active port mapping from the gateway.
func (pf *PortForwarder) UnmapPort(ctx context.Context) error {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.mapping == nil {
		return nil
	}

	pf.stopRenewal()

	var err error
	switch {
	case pf.igd2Client != nil:
		err = pf.igd2Client.DeletePortMappingCtx(ctx, "", pf.mapping.ExternalPort, pf.mapping.Protocol)
	case pf.igd1Client != nil:
		err = pf.igd1Client.DeletePortMappingCtx(ctx, "", pf.mapping.ExternalPort, pf.mapping.Protocol)
	}

	pf.mapping = nil
	pf.igd2Client = nil
	pf.igd1Client = nil
	return err
}

// Mapping returns the current active mapping, or nil if none.
func (pf *PortForwarder) Mapping() *PortMapping {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return pf.mapping
}

// StartRenewal begins a background goroutine that refreshes the port mapping
// at half the lease interval. Call UnmapPort to stop it.
func (pf *PortForwarder) StartRenewal(ctx context.Context) {
	pf.mu.Lock()
	if pf.mapping == nil || pf.stopC != nil {
		pf.mu.Unlock()
		return
	}
	pf.stopC = make(chan struct{})
	mapping := *pf.mapping
	pf.mu.Unlock()

	renewInterval := mapping.LeaseDuration / 2
	if renewInterval < time.Minute {
		renewInterval = time.Minute
	}

	go func() {
		ticker := time.NewTicker(renewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pf.mu.Lock()
				if pf.mapping == nil {
					pf.mu.Unlock()
					return
				}
				// Re-add the same mapping to refresh the lease
				switch {
				case pf.igd2Client != nil:
					_ = pf.igd2Client.AddPortMappingCtx(ctx,
						"", mapping.ExternalPort, mapping.Protocol,
						mapping.InternalPort, mapping.InternalIP,
						true, "Lantern Peer Proxy",
						uint32(mapping.LeaseDuration.Seconds()),
					)
				case pf.igd1Client != nil:
					_ = pf.igd1Client.AddPortMappingCtx(ctx,
						"", mapping.ExternalPort, mapping.Protocol,
						mapping.InternalPort, mapping.InternalIP,
						true, "Lantern Peer Proxy",
						uint32(mapping.LeaseDuration.Seconds()),
					)
				}
				pf.mu.Unlock()
			case <-pf.stopC:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (pf *PortForwarder) stopRenewal() {
	if pf.stopC != nil {
		close(pf.stopC)
		pf.stopC = nil
	}
}

const (
	maxRetries    = 10
	leaseDuration = 3600 // 1 hour in seconds
	portRangeMin  = 10000
	portRangeMax  = 60000
)

func (pf *PortForwarder) tryIGD2(ctx context.Context, localIP string, internalPort uint16, desc string) (*PortMapping, error) {
	clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv2 gateway found")
	}
	client := clients[0]

	for i := 0; i < maxRetries; i++ {
		extPort := randomPort()
		err = client.AddPortMappingCtx(ctx,
			"",       // RemoteHost (any)
			extPort,  // ExternalPort
			"TCP",    // Protocol
			internalPort,
			localIP,
			true,     // Enabled
			desc,
			leaseDuration,
		)
		if err == nil {
			pf.igd2Client = client
			return &PortMapping{
				ExternalPort:  extPort,
				InternalPort:  internalPort,
				InternalIP:    localIP,
				Protocol:      "TCP",
				LeaseDuration: time.Duration(leaseDuration) * time.Second,
				Method:        "upnp-igd2",
			}, nil
		}
	}
	return nil, fmt.Errorf("IGDv2 port mapping failed after %d attempts: %w", maxRetries, err)
}

func (pf *PortForwarder) tryIGD1(ctx context.Context, localIP string, internalPort uint16, desc string) (*PortMapping, error) {
	clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv1 gateway found")
	}
	client := clients[0]

	for i := 0; i < maxRetries; i++ {
		extPort := randomPort()
		err = client.AddPortMappingCtx(ctx,
			"",
			extPort,
			"TCP",
			internalPort,
			localIP,
			true,
			desc,
			leaseDuration,
		)
		if err == nil {
			pf.igd1Client = client
			return &PortMapping{
				ExternalPort:  extPort,
				InternalPort:  internalPort,
				InternalIP:    localIP,
				Protocol:      "TCP",
				LeaseDuration: time.Duration(leaseDuration) * time.Second,
				Method:        "upnp-igd1",
			}, nil
		}
	}
	return nil, fmt.Errorf("IGDv1 port mapping failed after %d attempts: %w", maxRetries, err)
}

// randomPort returns a random port in the range [portRangeMin, portRangeMax).
func randomPort() uint16 {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(portRangeMax-portRangeMin)))
	return uint16(n.Int64()) + portRangeMin
}

// localIPForGateway determines this machine's LAN IP by dialing a UDP socket
// to a well-known address and reading the local address. No actual traffic is sent.
func localIPForGateway() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), nil
}
