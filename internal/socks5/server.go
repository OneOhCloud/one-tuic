package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/OneOhCloud/one-tuic/internal/outbound"
)

const (
	socks5Version = 0x05

	// Authentication methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xff

	// Commands
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	repSuccess                 = 0x00
	repGeneralFailure          = 0x01
	repConnectionRefused       = 0x05
	repCommandNotSupported     = 0x07
	repAddressTypeNotSupported = 0x08
)

// Config represents SOCKS5 server configuration
type Config struct {
	Addr          string
	Username      string
	Password      string
	MaxPacketSize int
}

// Server represents a SOCKS5 proxy server
type Server struct {
	cfg      Config
	listener net.Listener
	outbound outbound.Outbound
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	logger   *slog.Logger
}

// NewServer creates a new SOCKS5 server with the given outbound
func NewServer(cfg Config, out outbound.Outbound, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 1500
	}

	return &Server{
		cfg:      cfg,
		outbound: out,
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
	}
}

// Start starts the SOCKS5 server
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.Addr, err)
	}
	s.listener = listener
	s.logger.Info("SOCKS5 server started", "addr", s.cfg.Addr, "outbound", s.outbound.Name())

	go s.acceptLoop()
	return nil
}

// Stop stops the SOCKS5 server
func (s *Server) Stop() error {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("failed to accept connection", "error", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()

	if err := s.handshake(conn); err != nil {
		s.logger.Debug("handshake failed", "client", clientAddr, "error", err)
		return
	}

	cmd, addr, err := s.readCommand(conn)
	if err != nil {
		s.logger.Debug("failed to read command", "client", clientAddr, "error", err)
		return
	}

	switch cmd {
	case cmdConnect:
		s.handleConnect(conn, addr, clientAddr)
	case cmdUDPAssociate:
		s.handleUDPAssociate(conn, addr, clientAddr)
	case cmdBind:
		s.sendReply(conn, repCommandNotSupported, nil)
	default:
		s.sendReply(conn, repCommandNotSupported, nil)
	}
}

func (s *Server) handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	if s.cfg.Username != "" && s.cfg.Password != "" {
		hasPasswordAuth := false
		for _, m := range methods {
			if m == authPassword {
				hasPasswordAuth = true
				break
			}
		}

		if !hasPasswordAuth {
			conn.Write([]byte{socks5Version, authNoAccept})
			return errors.New("password authentication required but not offered")
		}

		if _, err := conn.Write([]byte{socks5Version, authPassword}); err != nil {
			return err
		}

		if err := s.authenticatePassword(conn); err != nil {
			return err
		}
	} else {
		hasNoAuth := false
		for _, m := range methods {
			if m == authNone {
				hasNoAuth = true
				break
			}
		}

		if !hasNoAuth {
			conn.Write([]byte{socks5Version, authNoAccept})
			return errors.New("no acceptable authentication method")
		}

		if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) authenticatePassword(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	usernameLen := int(header[1])
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passwordLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLenBuf); err != nil {
		return err
	}

	passwordLen := int(passwordLenBuf[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) != s.cfg.Username || string(password) != s.cfg.Password {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("authentication failed")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func (s *Server) readCommand(conn net.Conn) (byte, outbound.Address, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, outbound.Address{}, fmt.Errorf("failed to read command header: %w", err)
	}

	if header[0] != socks5Version {
		return 0, outbound.Address{}, fmt.Errorf("invalid SOCKS version: %d", header[0])
	}

	cmd := header[1]
	atyp := header[3]

	var addr outbound.Address

	switch atyp {
	case atypIPv4:
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return 0, outbound.Address{}, err
		}
		addr.Type = outbound.AddressTypeIPv4
		addr.Host = net.IP(addrBytes).String()

	case atypIPv6:
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return 0, outbound.Address{}, err
		}
		addr.Type = outbound.AddressTypeIPv6
		addr.Host = net.IP(addrBytes).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return 0, outbound.Address{}, err
		}
		domainBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			return 0, outbound.Address{}, err
		}
		addr.Type = outbound.AddressTypeDomain
		addr.Host = string(domainBytes)

	default:
		s.sendReply(conn, repAddressTypeNotSupported, nil)
		return 0, outbound.Address{}, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, outbound.Address{}, err
	}
	addr.Port = binary.BigEndian.Uint16(portBuf)

	return cmd, addr, nil
}

func (s *Server) handleConnect(conn net.Conn, addr outbound.Address, clientAddr string) {
	s.logger.Info("connect", "client", clientAddr, "target", fmt.Sprintf("%s:%d", addr.Host, addr.Port))

	remote, err := s.outbound.DialTCP(s.ctx, addr)
	if err != nil {
		s.logger.Error("failed to dial", "error", err)
		s.sendReply(conn, repConnectionRefused, nil)
		return
	}
	defer remote.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	s.sendReply(conn, repSuccess, localAddr)

	relay(conn, remote)
}

func (s *Server) handleUDPAssociate(conn net.Conn, addr outbound.Address, clientAddr string) {
	s.logger.Info("UDP associate", "client", clientAddr)

	udpConn, err := s.outbound.DialUDP(s.ctx)
	if err != nil {
		s.logger.Error("failed to create UDP session", "error", err)
		s.sendReply(conn, repGeneralFailure, nil)
		return
	}
	defer udpConn.Close()

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		s.logger.Error("failed to create UDP listener", "error", err)
		s.sendReply(conn, repGeneralFailure, nil)
		return
	}
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)
	tcpAddr := conn.LocalAddr().(*net.TCPAddr)
	bindAddr := &net.TCPAddr{IP: tcpAddr.IP, Port: localAddr.Port}
	s.sendReply(conn, repSuccess, bindAddr)

	s.logger.Debug("UDP associate ready", "client", clientAddr, "udp_port", localAddr.Port)

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.relayUDPClientToServer(ctx, udpListener, udpConn)
	}()

	go func() {
		defer wg.Done()
		s.relayUDPServerToClient(ctx, udpListener, udpConn)
	}()

	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			cancel()
			break
		}
	}

	wg.Wait()
}

func (s *Server) relayUDPClientToServer(ctx context.Context, udpListener *net.UDPConn, udpConn outbound.UDPConn) {
	buf := make([]byte, s.cfg.MaxPacketSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}

		if n < 10 {
			continue
		}

		data := buf[:n]
		if data[0] != 0 || data[1] != 0 {
			continue
		}

		frag := data[2]
		if frag != 0 {
			continue
		}

		atyp := data[3]
		var addr outbound.Address
		var dataStart int

		switch atyp {
		case atypIPv4:
			if n < 10 {
				continue
			}
			addr.Type = outbound.AddressTypeIPv4
			addr.Host = net.IP(data[4:8]).String()
			addr.Port = binary.BigEndian.Uint16(data[8:10])
			dataStart = 10
		case atypIPv6:
			if n < 22 {
				continue
			}
			addr.Type = outbound.AddressTypeIPv6
			addr.Host = net.IP(data[4:20]).String()
			addr.Port = binary.BigEndian.Uint16(data[20:22])
			dataStart = 22
		case atypDomain:
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			addr.Type = outbound.AddressTypeDomain
			addr.Host = string(data[5 : 5+domainLen])
			addr.Port = binary.BigEndian.Uint16(data[5+domainLen : 7+domainLen])
			dataStart = 7 + domainLen
		default:
			continue
		}

		payload := data[dataStart:]
		if err := udpConn.SendPacket(payload, addr); err != nil {
			s.logger.Debug("failed to send UDP packet", "error", err)
		}
	}
}

func (s *Server) relayUDPServerToClient(ctx context.Context, udpListener *net.UDPConn, udpConn outbound.UDPConn) {
	for {
		pkt, err := udpConn.RecvPacket(ctx)
		if err != nil {
			return
		}

		var header []byte
		header = append(header, 0, 0, 0) // RSV + FRAG

		switch pkt.Address.Type {
		case outbound.AddressTypeIPv4:
			header = append(header, atypIPv4)
			ip := net.ParseIP(pkt.Address.Host).To4()
			header = append(header, ip...)
		case outbound.AddressTypeIPv6:
			header = append(header, atypIPv6)
			ip := net.ParseIP(pkt.Address.Host).To16()
			header = append(header, ip...)
		case outbound.AddressTypeDomain:
			header = append(header, atypDomain)
			header = append(header, byte(len(pkt.Address.Host)))
			header = append(header, []byte(pkt.Address.Host)...)
		default:
			continue
		}

		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, pkt.Address.Port)
		header = append(header, portBuf...)

		response := append(header, pkt.Data...)
		_, _ = udpListener.Write(response)
	}
}

func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	var reply []byte

	if bindAddr == nil {
		reply = []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	} else {
		ip := bindAddr.IP.To4()
		if ip == nil {
			ip = bindAddr.IP.To16()
			reply = make([]byte, 4+16+2)
			reply[0] = socks5Version
			reply[1] = rep
			reply[2] = 0x00
			reply[3] = atypIPv6
			copy(reply[4:20], ip)
			binary.BigEndian.PutUint16(reply[20:22], uint16(bindAddr.Port))
		} else {
			reply = make([]byte, 4+4+2)
			reply[0] = socks5Version
			reply[1] = rep
			reply[2] = 0x00
			reply[3] = atypIPv4
			copy(reply[4:8], ip)
			binary.BigEndian.PutUint16(reply[8:10], uint16(bindAddr.Port))
		}
	}

	conn.Write(reply)
}

func relay(dst, src io.ReadWriteCloser) {
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
