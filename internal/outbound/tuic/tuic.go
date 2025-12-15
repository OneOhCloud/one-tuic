package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
	cfg    Config
	conn   *quic.Conn
	udpMgr *udpSessionManager
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
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

	return o.connectLocked(ctx)
}

func (o *Outbound) connectLocked(ctx context.Context) error {
	// Close existing connection if any
	if o.conn != nil {
		o.conn.CloseWithError(0, "reconnecting")
		o.conn = nil
		o.udpMgr = nil
	}

	conn, err := o.dial(ctx)
	if err != nil {
		return err
	}

	o.conn = conn

	// Initialize UDP session manager
	mode := UDPModeNative
	if o.cfg.UDPRelayMode == "quic" {
		mode = UDPModeQuic
	}
	o.udpMgr = newUDPSessionManager(conn, mode, o.ctx)

	// Perform authentication synchronously to ensure it completes before returning
	if err := o.authenticateLocked(); err != nil {
		o.conn.CloseWithError(0, "auth failed")
		o.conn = nil
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Start heartbeat
	go o.runHeartbeat(conn)

	return nil
}

func (o *Outbound) dial(ctx context.Context) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(o.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

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

	timeout := o.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	return quic.DialAddr(dialCtx, addr.String(), tlsConfig, quicConfig)
}

func (o *Outbound) authenticateLocked() error {
	stream, err := o.conn.OpenUniStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	state := o.conn.ConnectionState()
	tlsState := state.TLS

	label := string(o.cfg.UUID[:])
	token, err := tlsState.ExportKeyingMaterial(label, []byte(o.cfg.Password), 32)
	if err != nil {
		return err
	}

	var tokenArr [32]byte
	copy(tokenArr[:], token)

	authCmd := protocol.EncodeAuthenticate(o.cfg.UUID, tokenArr)
	if _, err := stream.Write(authCmd); err != nil {
		return err
	}

	return nil
}

func (o *Outbound) runHeartbeat(conn *quic.Conn) {
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
			o.mu.Lock()
			if o.conn != conn {
				o.mu.Unlock()
				return
			}
			if conn.ConnectionState().SupportsDatagrams {
				heartbeat := protocol.EncodeHeartbeat()
				_ = conn.SendDatagram(heartbeat)
			}
			o.mu.Unlock()
		}
	}
}

func (o *Outbound) isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Application error 0x0") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "use of closed") ||
		strings.Contains(errStr, "timeout")
}

func (o *Outbound) getConnWithRetry(ctx context.Context) (*quic.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.conn == nil {
		if err := o.connectLocked(ctx); err != nil {
			return nil, err
		}
	}

	return o.conn, nil
}

func (o *Outbound) reconnect(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.connectLocked(ctx)
}

// DialTCP implements outbound.Outbound
func (o *Outbound) DialTCP(ctx context.Context, addr outbound.Address) (outbound.TCPConn, error) {
	conn, err := o.getConnWithRetry(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Connection might be closed, try to reconnect
		if o.isConnectionClosed(err) {
			if reconnErr := o.reconnect(ctx); reconnErr != nil {
				return nil, fmt.Errorf("failed to reconnect: %w", reconnErr)
			}

			conn, err = o.getConnWithRetry(ctx)
			if err != nil {
				return nil, err
			}

			stream, err = conn.OpenStreamSync(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to open stream after reconnect: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to open stream: %w", err)
		}
	}

	tuicAddr := protocol.Address{
		Type: protocol.AddressType(addr.Type),
		Host: addr.Host,
		Port: addr.Port,
	}

	connectCmd := protocol.EncodeConnect(tuicAddr)
	if _, err := stream.Write(connectCmd); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to send connect command: %w", err)
	}

	return &tcpConn{stream: stream}, nil
}

// DialUDP implements outbound.Outbound
func (o *Outbound) DialUDP(ctx context.Context) (outbound.UDPConn, error) {
	if _, err := o.getConnWithRetry(ctx); err != nil {
		return nil, err
	}

	o.mu.Lock()
	session := o.udpMgr.newSession()
	o.mu.Unlock()

	return &udpConn{session: session}, nil
}

// Close implements outbound.Outbound
func (o *Outbound) Close() error {
	o.cancel()
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.conn != nil {
		err := o.conn.CloseWithError(0, "client closing")
		o.conn = nil
		return err
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
