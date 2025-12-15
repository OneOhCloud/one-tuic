package outbound

import (
	"context"
	"io"
)

// Address represents a network address
type Address struct {
	Type AddressType
	Host string
	Port uint16
}

// AddressType represents the type of address
type AddressType byte

const (
	AddressTypeNone   AddressType = 0xff
	AddressTypeDomain AddressType = 0x00
	AddressTypeIPv4   AddressType = 0x01
	AddressTypeIPv6   AddressType = 0x02
)

// UDPPacket represents a UDP packet with address
type UDPPacket struct {
	Data    []byte
	Address Address
}

// TCPConn represents a TCP connection that can be read/written and closed
type TCPConn interface {
	io.ReadWriteCloser
}

// UDPConn represents a UDP session for sending/receiving packets
type UDPConn interface {
	// SendPacket sends a UDP packet to the specified address
	SendPacket(data []byte, addr Address) error

	// RecvPacket receives a UDP packet, blocks until packet arrives or context is cancelled
	RecvPacket(ctx context.Context) (*UDPPacket, error)

	// LocalAddr returns the local address (for SOCKS5 UDP associate reply)
	LocalAddr() string

	// Close closes the UDP session
	Close() error
}

// Outbound defines the interface for outbound connections
// This allows different implementations (TUIC, direct, other proxies)
type Outbound interface {
	// DialTCP establishes a TCP connection to the target address
	DialTCP(ctx context.Context, addr Address) (TCPConn, error)

	// DialUDP creates a UDP session for packet relay
	DialUDP(ctx context.Context) (UDPConn, error)

	// Close closes the outbound and releases resources
	Close() error

	// Name returns the name of this outbound
	Name() string
}
