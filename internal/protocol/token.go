package protocol

import (
	"crypto/tls"
	"fmt"
)

// TLSExporter is an interface for TLS connections that can export keying material
type TLSExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// DeriveToken derives the authentication token using TLS Keying Material Exporter
// The label is the UUID bytes and context is the raw password
func DeriveToken(exporter TLSExporter, uuid [16]byte, password []byte) ([32]byte, error) {
	var token [32]byte

	// Export keying material with UUID as label and password as context
	// This follows the TUIC protocol specification
	label := string(uuid[:])
	exported, err := exporter.ExportKeyingMaterial(label, password, 32)
	if err != nil {
		return token, fmt.Errorf("failed to export keying material: %w", err)
	}

	copy(token[:], exported)
	return token, nil
}

// DeriveTokenFromState derives the token from a TLS connection state
func DeriveTokenFromState(state tls.ConnectionState, uuid [16]byte, password []byte) ([32]byte, error) {
	var token [32]byte

	label := string(uuid[:])
	exported, err := state.ExportKeyingMaterial(label, password, 32)
	if err != nil {
		return token, fmt.Errorf("failed to export keying material: %w", err)
	}

	copy(token[:], exported)
	return token, nil
}
