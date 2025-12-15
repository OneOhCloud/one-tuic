package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

// Config represents the client configuration
type Config struct {
	Relay    RelayConfig `json:"relay"`
	Local    LocalConfig `json:"local"`
	LogLevel string      `json:"log_level"`
}

// RelayConfig represents the relay server configuration
type RelayConfig struct {
	Server         string   `json:"server"`
	UUID           string   `json:"uuid"`
	Password       string   `json:"password"`
	IP             string   `json:"ip,omitempty"`
	Certificates   []string `json:"certificates,omitempty"`
	UDPRelayMode   string   `json:"udp_relay_mode"`
	CongestionCtrl string   `json:"congestion_control"`
	ZeroRTT        bool     `json:"zero_rtt_handshake"`
	DisableSNI     bool     `json:"disable_sni"`
	SNI            string   `json:"sni,omitempty"`
	Timeout        Duration `json:"timeout"`
	Heartbeat      Duration `json:"heartbeat"`
	SkipCertVerify bool     `json:"skip_cert_verify"`
	ALPN           []string `json:"alpn,omitempty"`
	SendWindow     uint64   `json:"send_window"`
	ReceiveWindow  uint32   `json:"receive_window"`
	InitialMTU     uint16   `json:"initial_mtu"`
	MinMTU         uint16   `json:"min_mtu"`
	GSO            bool     `json:"gso"`
	PMTU           bool     `json:"pmtu"`
	GCInterval     Duration `json:"gc_interval"`
	GCLifetime     Duration `json:"gc_lifetime"`
}

// LocalConfig represents the local SOCKS5 server configuration
type LocalConfig struct {
	Server        string `json:"server"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	DualStack     *bool  `json:"dual_stack,omitempty"`
	MaxPacketSize int    `json:"max_packet_size"`
}

// Duration is a wrapper for time.Duration with JSON support
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// GetUUID parses and returns the UUID from config
func (c *RelayConfig) GetUUID() ([16]byte, error) {
	id, err := uuid.Parse(c.UUID)
	if err != nil {
		return [16]byte{}, fmt.Errorf("invalid UUID: %w", err)
	}
	return id, nil
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{
		LogLevel: "info",
		Relay: RelayConfig{
			UDPRelayMode:   "native",
			CongestionCtrl: "bbr",
			Timeout:        Duration{8 * time.Second},
			Heartbeat:      Duration{3 * time.Second},
			SendWindow:     16 * 1024 * 1024,
			ReceiveWindow:  8 * 1024 * 1024,
			InitialMTU:     1200,
			MinMTU:         1200,
			GSO:            true,
			PMTU:           true,
			GCInterval:     Duration{3 * time.Second},
			GCLifetime:     Duration{15 * time.Second},
		},
		Local: LocalConfig{
			Server:        "127.0.0.1:1080",
			MaxPacketSize: 1500,
		},
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	if cfg.Relay.Server == "" {
		return nil, fmt.Errorf("relay.server is required")
	}
	if cfg.Relay.UUID == "" {
		return nil, fmt.Errorf("relay.uuid is required")
	}
	if cfg.Relay.Password == "" {
		return nil, fmt.Errorf("relay.password is required")
	}

	return cfg, nil
}
