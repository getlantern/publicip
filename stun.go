package publicip

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// STUN constants (RFC 5389)
const (
	stunMagicCookie    = 0x2112A442
	stunBindingRequest = 0x0001
	stunHeaderSize     = 20
	stunAttrXORMapped  = 0x0020
	stunAttrMapped     = 0x0001
)

type stunMethod struct {
	server string
}

// NewSTUN creates a STUN-based IP detection method using raw UDP.
// No external dependencies needed — implements minimal RFC 5389.
func NewSTUN(server string) Method {
	return &stunMethod{server: server}
}

func (s *stunMethod) Name() string {
	return "stun:" + s.server
}

func (s *stunMethod) Detect(ctx context.Context) (net.IP, *GeoInfo, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", s.server)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", s.server, err)
	}
	defer conn.Close()

	// Build STUN Binding Request (RFC 5389 Section 6)
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, nil, err
	}

	req := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest) // Message Type
	binary.BigEndian.PutUint16(req[2:4], 0)                  // Message Length (no attrs)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)    // Magic Cookie
	copy(req[8:20], txID[:])                                  // Transaction ID

	if _, err := conn.Write(req); err != nil {
		return nil, nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("read: %w", err)
	}
	if n < stunHeaderSize {
		return nil, nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Parse response — look for XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
	msgLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if stunHeaderSize+msgLen > n {
		return nil, nil, fmt.Errorf("truncated response")
	}

	ip := parseSTUNAttributes(buf[stunHeaderSize:stunHeaderSize+msgLen], txID)
	if ip == nil {
		return nil, nil, fmt.Errorf("no address in STUN response")
	}
	return ip, nil, nil
}

func parseSTUNAttributes(attrs []byte, txID [12]byte) net.IP {
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+attrLen > len(attrs) {
			break
		}
		val := attrs[4 : 4+attrLen]

		switch attrType {
		case stunAttrXORMapped:
			return parseXORMappedAddress(val, txID)
		case stunAttrMapped:
			return parseMappedAddress(val)
		}

		// Attributes are padded to 4-byte boundaries
		padded := attrLen + (4-attrLen%4)%4
		attrs = attrs[4+padded:]
	}
	return nil
}

func parseXORMappedAddress(val []byte, txID [12]byte) net.IP {
	if len(val) < 8 {
		return nil
	}
	family := val[1]
	switch family {
	case 0x01: // IPv4
		if len(val) < 8 {
			return nil
		}
		ip := make(net.IP, 4)
		// XOR port and address with magic cookie
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, stunMagicCookie)
		for i := 0; i < 4; i++ {
			ip[i] = val[4+i] ^ magic[i]
		}
		return ip
	case 0x02: // IPv6
		if len(val) < 20 {
			return nil
		}
		ip := make(net.IP, 16)
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, stunMagicCookie)
		xorKey := append(magic, txID[:]...)
		for i := 0; i < 16; i++ {
			ip[i] = val[4+i] ^ xorKey[i]
		}
		return ip
	}
	return nil
}

func parseMappedAddress(val []byte) net.IP {
	if len(val) < 8 {
		return nil
	}
	family := val[1]
	switch family {
	case 0x01: // IPv4
		return net.IP(val[4:8])
	case 0x02: // IPv6
		if len(val) < 20 {
			return nil
		}
		return net.IP(val[4:20])
	}
	return nil
}
