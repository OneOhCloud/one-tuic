package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OneOhCloud/one-tuic/internal/outbound"
	"github.com/OneOhCloud/one-tuic/internal/protocol"
	"github.com/quic-go/quic-go"
)

// Config represents TUIC outbound configuration
type Config struct {
	Server         string
	UUID           [16]byte
	Password       string
	UDPRelayMode   string // "native" or "quic"
	CongestionCtrl string
	ZeroRTT        bool
	DisableSNI     bool
	SNI            string
	Timeout        time.Duration
	Heartbeat      time.Duration
	SkipCertVerify bool
	ALPN           []string
	SendWindow     uint64
	ReceiveWindow  uint32
}

// Outbound implements outbound.Outbound for TUIC protocol
type Outbound struct {
	cfg         Config
	conn        *quic.Conn
	udpMgr      *udpSessionManager
	isConnected atomic.Bool
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// New creates a new TUIC outbound
func New(cfg Config) *Outbound {
	ctx, cancel := context.WithCancel(context.Background())
	return &Outbound{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Connect establishes connection to TUIC server
func (o *Outbound) Connect(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.isConnected.Load() {
		return nil
	}

	conn, err := o.dial(ctx)
	if err != nil {
		return err
	}

	o.conn = conn
	o.isConnected.Store(true)

	// Initialize UDP session manager
	mode := UDPModeNative
	if o.cfg.UDPRelayMode == "quic" {
		mode = UDPModeQuic
	}
	o.udpMgr = newUDPSessionManager(conn, mode, o.ctx)

	// Start authentication
	go o.authenticate()

	// Start heartbeat
	go o.runHeartbeat()

	return nil
}

func (o *Outbound) dial(ctx context.Context) (*quic.Conn, error) {
	// Resolve server address
	host, port, err := net.SplitHostPort(o.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		NextProtos:         o.cfg.ALPN,
		InsecureSkipVerify: o.cfg.SkipCertVerify,
	}

	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h3"}
	}

	if o.cfg.SNI != "" {
		tlsConfig.ServerName = o.cfg.SNI
	} else if !o.cfg.DisableSNI {
		tlsConfig.ServerName = host
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                o.cfg.Heartbeat,
		InitialStreamReceiveWindow:     uint64(o.cfg.ReceiveWindow),
		MaxStreamReceiveWindow:         uint64(o.cfg.ReceiveWindow),
		InitialConnectionReceiveWindow: o.cfg.SendWindow,
		MaxConnectionReceiveWindow:     o.cfg.SendWindow,
		EnableDatagrams:                o.cfg.UDPRelayMode == "native",
		Allow0RTT:                      o.cfg.ZeroRTT,
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, o.cfg.Timeout)
	defer dialCancel()

	return quic.DialAddr(dialCtx, addr.String(), tlsConfig, quicConfig)
}

func (o *Outbound) authenticate() {
	stream, err := o.conn.OpenUniStream()
	if err != nil {
		o.Close()
		return
	}

	// Derive token using TLS keying material exporter
	state := o.conn.ConnectionState()
	tlsState := state.TLS

	label := string(o.cfg.UUID[:])
	token, err := tlsState.ExportKeyingMaterial(label, []byte(o.cfg.Password), 32)
	if err != nil {
		stream.Close()
		o.Close()
		return
	}

	var tokenArr [32]byte
	copy(tokenArr[:], token)

	authCmd := protocol.EncodeAuthenticate(o.cfg.UUID, tokenArr)
	if _, err := stream.Write(authCmd); err != nil {
		stream.Close()
		o.Close()
		return
	}

	stream.Close()
}

func (o *Outbound) runHeartbeat() {
	if o.cfg.Heartbeat <= 0 {
		return
	}

	ticker := time.NewTicker(o.cfg.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			if o.conn.ConnectionState().SupportsDatagrams {
				heartbeat := protocol.EncodeHeartbeat()
				_ = o.conn.SendDatagram(heartbeat)
			}
		}
	}
}

func (o *Outbound) getConn(ctx context.Context) (*quic.Conn, error) {
	if !o.isConnected.Load() {
		if err := o.Connect(ctx); err != nil {
			return nil, err
		}
	}
	return o.conn, nil
}

// DialTCP implements outbound.Outbound
func (o *Outbound) DialTCP(ctx context.Context, addr outbound.Address) (outbound.TCPConn, error) {
	conn, err := o.getConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Convert address
	tuicAddr := protocol.Address{
		Type: protocol.AddressType(addr.Type),
		Host: addr.Host,
		Port: addr.Port,
	}

	// Send Connect command
	connectCmd := protocol.EncodeConnect(tuicAddr)
	if _, err := stream.Write(connectCmd); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to send connect command: %w", err)
	}

	return &tcpConn{stream: stream}, nil
}

// DialUDP implements outbound.Outbound
func (o *Outbound) DialUDP(ctx context.Context) (outbound.UDPConn, error) {
	if _, err := o.getConn(ctx); err != nil {
		return nil, err
	}

	session := o.udpMgr.newSession()
	return &udpConn{session: session}, nil
}

// Close implements outbound.Outbound
func (o *Outbound) Close() error {
	o.isConnected.Store(false)
	o.cancel()
	if o.conn != nil {
		return o.conn.CloseWithError(0, "client closing")
	}
	return nil
}

// Name implements outbound.Outbound
func (o *Outbound) Name() string {
	return "tuic"
}

// tcpConn wraps a QUIC stream as outbound.TCPConn
type tcpConn struct {
	stream *quic.Stream
}

func (c *tcpConn) Read(p []byte) (n int, err error) {
	return c.stream.Read(p)
}

func (c *tcpConn) Write(p []byte) (n int, err error) {
	return c.stream.Write(p)
}

func (c *tcpConn) Close() error {
	return c.stream.Close()
}

// udpConn wraps a UDP session as outbound.UDPConn
type udpConn struct {
	session *udpSession
}

func (c *udpConn) SendPacket(data []byte, addr outbound.Address) error {
	tuicAddr := protocol.Address{
		Type: protocol.AddressType(addr.Type),
		Host: addr.Host,
		Port: addr.Port,
	}
	return c.session.sendPacket(data, tuicAddr)
}

func (c *udpConn) RecvPacket(ctx context.Context) (*outbound.UDPPacket, error) {
	pkt, err := c.session.recvPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &outbound.UDPPacket{
		Data: pkt.Data,
		Address: outbound.Address{
			Type: outbound.AddressType(pkt.Address.Type),
			Host: pkt.Address.Host,
			Port: pkt.Address.Port,
		},
	}, nil
}

func (c *udpConn) LocalAddr() string {
	return fmt.Sprintf("0.0.0.0:%d", c.session.assocID)
}

func (c *udpConn) Close() error {
	return c.session.close()
}

// Relay copies data bidirectionally between two connections
func Relay(dst, src io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(src, dst)
		if closer, ok := src.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

	wg.Wait()
}
