package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// AddressType represents the type of address
type AddressType byte

const (
	AddressTypeNone   AddressType = 0xff
	AddressTypeDomain AddressType = 0x00
	AddressTypeIPv4   AddressType = 0x01
	AddressTypeIPv6   AddressType = 0x02
)

// Address represents a network address in TUIC protocol
type Address struct {
	Type AddressType
	Host string
	Port uint16
}

// NewAddress creates an Address from host and port
func NewAddress(host string, port uint16) Address {
	addr := Address{Port: port}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr.Type = AddressTypeIPv4
			addr.Host = ip4.String()
		} else {
			addr.Type = AddressTypeIPv6
			addr.Host = ip.String()
		}
	} else {
		addr.Type = AddressTypeDomain
		addr.Host = host
	}

	return addr
}

// NewAddressFromSocks5 creates an Address from SOCKS5 address format
func NewAddressFromSocks5(atyp byte, addr []byte, port uint16) Address {
	a := Address{Port: port}

	switch atyp {
	case 0x01: // IPv4
		a.Type = AddressTypeIPv4
		a.Host = net.IP(addr).String()
	case 0x04: // IPv6
		a.Type = AddressTypeIPv6
		a.Host = net.IP(addr).String()
	case 0x03: // Domain
		a.Type = AddressTypeDomain
		a.Host = string(addr)
	}

	return a
}

// Encode encodes the address to bytes for TUIC protocol
func (a *Address) Encode() []byte {
	var buf []byte

	buf = append(buf, byte(a.Type))

	switch a.Type {
	case AddressTypeDomain:
		buf = append(buf, byte(len(a.Host)))
		buf = append(buf, []byte(a.Host)...)
	case AddressTypeIPv4:
		ip := net.ParseIP(a.Host).To4()
		buf = append(buf, ip...)
	case AddressTypeIPv6:
		ip := net.ParseIP(a.Host).To16()
		buf = append(buf, ip...)
	case AddressTypeNone:
		// No address data for None type
	}

	// Append port (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, a.Port)
	buf = append(buf, portBytes...)

	return buf
}

// DecodeAddress reads and decodes an address from a reader
func DecodeAddress(r io.Reader) (Address, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return Address{}, fmt.Errorf("failed to read address type: %w", err)
	}

	addr := Address{Type: AddressType(typeBuf[0])}

	switch addr.Type {
	case AddressTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return Address{}, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return Address{}, fmt.Errorf("failed to read domain: %w", err)
		}
		addr.Host = string(domainBuf)

	case AddressTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return Address{}, fmt.Errorf("failed to read IPv4: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return Address{}, fmt.Errorf("failed to read IPv6: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeNone:
		// No address data

	default:
		return Address{}, fmt.Errorf("unknown address type: %d", addr.Type)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return Address{}, fmt.Errorf("failed to read port: %w", err)
	}
	addr.Port = binary.BigEndian.Uint16(portBuf)

	return addr, nil
}

func (a Address) String() string {
	if a.Type == AddressTypeNone {
		return "<none>"
	}
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}
