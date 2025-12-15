package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ProtocolVersion byte = 0x05
)

// CommandType represents the TUIC command type
type CommandType byte

const (
	CommandAuthenticate CommandType = 0x00
	CommandConnect      CommandType = 0x01
	CommandPacket       CommandType = 0x02
	CommandDissociate   CommandType = 0x03
	CommandHeartbeat    CommandType = 0x04
)

// Header represents the TUIC command header
type Header struct {
	Version byte
	Type    CommandType
}

// Authenticate command
type Authenticate struct {
	Header
	UUID  [16]byte
	Token [32]byte
}

// Connect command
type Connect struct {
	Header
	Address Address
}

// Packet command
type Packet struct {
	Header
	AssocID   uint16
	PacketID  uint16
	FragTotal uint8
	FragID    uint8
	Size      uint16
	Address   Address
}

// Dissociate command
type Dissociate struct {
	Header
	AssocID uint16
}

// Heartbeat command
type Heartbeat struct {
	Header
}

// EncodeAuthenticate encodes an Authenticate command
func EncodeAuthenticate(uuid [16]byte, token [32]byte) []byte {
	buf := make([]byte, 2+16+32)
	buf[0] = ProtocolVersion
	buf[1] = byte(CommandAuthenticate)
	copy(buf[2:18], uuid[:])
	copy(buf[18:50], token[:])
	return buf
}

// EncodeConnect encodes a Connect command
func EncodeConnect(addr Address) []byte {
	addrBytes := addr.Encode()
	buf := make([]byte, 2+len(addrBytes))
	buf[0] = ProtocolVersion
	buf[1] = byte(CommandConnect)
	copy(buf[2:], addrBytes)
	return buf
}

// EncodePacket encodes a Packet command header
func EncodePacket(assocID, packetID uint16, fragTotal, fragID uint8, size uint16, addr Address) []byte {
	addrBytes := addr.Encode()
	buf := make([]byte, 2+2+2+1+1+2+len(addrBytes))
	buf[0] = ProtocolVersion
	buf[1] = byte(CommandPacket)
	binary.BigEndian.PutUint16(buf[2:4], assocID)
	binary.BigEndian.PutUint16(buf[4:6], packetID)
	buf[6] = fragTotal
	buf[7] = fragID
	binary.BigEndian.PutUint16(buf[8:10], size)
	copy(buf[10:], addrBytes)
	return buf
}

// EncodeDissociate encodes a Dissociate command
func EncodeDissociate(assocID uint16) []byte {
	buf := make([]byte, 4)
	buf[0] = ProtocolVersion
	buf[1] = byte(CommandDissociate)
	binary.BigEndian.PutUint16(buf[2:4], assocID)
	return buf
}

// EncodeHeartbeat encodes a Heartbeat command
func EncodeHeartbeat() []byte {
	return []byte{ProtocolVersion, byte(CommandHeartbeat)}
}

// DecodeHeader decodes a command header from reader
func DecodeHeader(r io.Reader) (Header, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, fmt.Errorf("failed to read header: %w", err)
	}

	return Header{
		Version: buf[0],
		Type:    CommandType(buf[1]),
	}, nil
}

// DecodePacketHeader decodes a Packet command header (without the 2-byte header)
func DecodePacketHeader(r io.Reader) (Packet, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Packet{}, fmt.Errorf("failed to read packet header: %w", err)
	}

	pkt := Packet{
		AssocID:   binary.BigEndian.Uint16(buf[0:2]),
		PacketID:  binary.BigEndian.Uint16(buf[2:4]),
		FragTotal: buf[4],
		FragID:    buf[5],
		Size:      binary.BigEndian.Uint16(buf[6:8]),
	}

	addr, err := DecodeAddress(r)
	if err != nil {
		return Packet{}, fmt.Errorf("failed to decode packet address: %w", err)
	}
	pkt.Address = addr

	return pkt, nil
}
