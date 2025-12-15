package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
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
	cfg       Config
	conn      atomic.Pointer[quic.Conn]
	udpMgr    atomic.Pointer[udpSessionManager]
	connectMu sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
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
	o.connectMu.Lock()
	defer o.connectMu.Unlock()

	// Double check after acquiring lock
	if o.conn.Load() != nil {
		return nil
	}

	return o.doConnect(ctx)
}

func (o *Outbound) doConnect(ctx context.Context) error {
	// Close existing connection if any
	if oldConn := o.conn.Load(); oldConn != nil {
		(*oldConn).CloseWithError(0, "reconnecting")
	}

	conn, err := o.dial(ctx)
	if err != nil {
		return err
	}

	// Perform authentication before storing connection
	if err := o.authenticate(conn); err != nil {
		conn.CloseWithError(0, "auth failed")
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Initialize UDP session manager
	mode := UDPModeNative
	if o.cfg.UDPRelayMode == "quic" {
		mode = UDPModeQuic
	}
	udpMgr := newUDPSessionManager(conn, mode, o.ctx)

	// Store atomically
	o.conn.Store(conn)
	o.udpMgr.Store(udpMgr)

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

	// 优化 QUIC 配置以支持高并发
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                o.cfg.Heartbeat,
		InitialStreamReceiveWindow:     uint64(o.cfg.ReceiveWindow),
		MaxStreamReceiveWindow:         uint64(o.cfg.ReceiveWindow),
		InitialConnectionReceiveWindow: o.cfg.SendWindow,
		MaxConnectionReceiveWindow:     o.cfg.SendWindow,
		EnableDatagrams:                o.cfg.UDPRelayMode == "native",
		Allow0RTT:                      o.cfg.ZeroRTT,
		MaxIncomingStreams:             1 << 60,
		MaxIncomingUniStreams:          1 << 60,
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin"),
	}

	timeout := o.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	return quic.DialAddr(dialCtx, addr.String(), tlsConfig, quicConfig)
}

func (o *Outbound) authenticate(conn *quic.Conn) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	state := conn.ConnectionState()
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
			currentConn := o.conn.Load()
			if currentConn == nil || currentConn != conn {
				return
			}
			if conn.ConnectionState().SupportsDatagrams {
				heartbeat := protocol.EncodeHeartbeat()
				_ = conn.SendDatagram(heartbeat)
			}
		}
	}
}

// offer returns an active connection, creating a new one if necessary
func (o *Outbound) offer(ctx context.Context) (*quic.Conn, error) {
	o.connectMu.Lock()
	defer o.connectMu.Unlock()

	// Check if existing connection is still valid
	if conn := o.conn.Load(); conn != nil {
		select {
		case <-conn.Context().Done():
			// Connection is closed, need to create new one
		default:
			// Connection is active
			return conn, nil
		}
	}

	// Create new connection
	if err := o.doConnect(ctx); err != nil {
		return nil, err
	}
	return o.conn.Load(), nil
}

// DialTCP implements outbound.Outbound
func (o *Outbound) DialTCP(ctx context.Context, addr outbound.Address) (outbound.TCPConn, error) {
	conn, err := o.offer(ctx)
	if err != nil {
		return nil, err
	}

	// 使用非阻塞 OpenStream 提高并发性能
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	destination := protocol.Address{
		Type: protocol.AddressType(addr.Type),
		Host: addr.Host,
		Port: addr.Port,
	}

	// 返回延迟写入连接，Connect 命令会与第一个数据包合并发送
	return &tcpConn{stream: stream, destination: destination}, nil
}

// DialUDP implements outbound.Outbound
func (o *Outbound) DialUDP(ctx context.Context) (outbound.UDPConn, error) {
	if _, err := o.offer(ctx); err != nil {
		return nil, err
	}

	udpMgr := o.udpMgr.Load()
	if udpMgr == nil {
		return nil, fmt.Errorf("UDP manager not initialized")
	}

	session := udpMgr.newSession()
	return &udpConn{session: session}, nil
}

// Close implements outbound.Outbound
func (o *Outbound) Close() error {
	o.cancel()

	if conn := o.conn.Load(); conn != nil {
		return conn.CloseWithError(0, "client closing")
	}
	return nil
}

// Name implements outbound.Outbound
func (o *Outbound) Name() string {
	return "tuic"
}

// tcpConn wraps a QUIC stream as outbound.TCPConn with lazy write optimization
type tcpConn struct {
	stream         *quic.Stream
	destination    protocol.Address
	requestWritten bool
}

func (c *tcpConn) Read(p []byte) (n int, err error) {
	return c.stream.Read(p)
}

// Write 实现延迟写入优化：将 Connect 命令与第一个数据包合并发送，减少 RTT
func (c *tcpConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		// 将 Connect 命令和用户数据合并为一个包发送
		header := protocol.EncodeConnect(c.destination)
		combined := make([]byte, len(header)+len(p))
		copy(combined, header)
		copy(combined[len(header):], p)
		_, err = c.stream.Write(combined)
		if err != nil {
			return 0, err
		}
		c.requestWritten = true
		return len(p), nil
	}
	return c.stream.Write(p)
}

// CloseWrite 实现半关闭，通知对端写入完成
func (c *tcpConn) CloseWrite() error {
	return c.stream.Close()
}

func (c *tcpConn) Close() error {
	c.stream.CancelRead(0)
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
