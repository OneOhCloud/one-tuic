package tuic

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/OneOhCloud/one-tuic/internal/protocol"
	"github.com/quic-go/quic-go"
)

// UDPMode represents the UDP relay mode
type UDPMode string

const (
	UDPModeNative UDPMode = "native" // Use QUIC datagrams
	UDPModeQuic   UDPMode = "quic"   // Use QUIC unidirectional streams
)

// udpPacket represents a received UDP packet
type udpPacket struct {
	Data    []byte
	Address protocol.Address
}

// udpSession represents a UDP relay session
type udpSession struct {
	mgr       *udpSessionManager
	assocID   uint16
	packetID  atomic.Uint32
	recvChan  chan *udpPacket
	fragments sync.Map
	ctx       context.Context
	cancel    context.CancelFunc
}

// udpSessionManager manages UDP sessions
type udpSessionManager struct {
	conn     *quic.Conn
	mode     UDPMode
	sessions sync.Map
	nextID   atomic.Uint32
	ctx      context.Context
}

func newUDPSessionManager(conn *quic.Conn, mode UDPMode, ctx context.Context) *udpSessionManager {
	mgr := &udpSessionManager{
		conn: conn,
		mode: mode,
		ctx:  ctx,
	}
	go mgr.receiveLoop()
	return mgr
}

func (m *udpSessionManager) newSession() *udpSession {
	assocID := uint16(m.nextID.Add(1))
	ctx, cancel := context.WithCancel(m.ctx)
	session := &udpSession{
		mgr:      m,
		assocID:  assocID,
		recvChan: make(chan *udpPacket, 256),
		ctx:      ctx,
		cancel:   cancel,
	}
	m.sessions.Store(assocID, session)
	return session
}

func (m *udpSessionManager) getSession(assocID uint16) (*udpSession, bool) {
	if session, ok := m.sessions.Load(assocID); ok {
		return session.(*udpSession), true
	}
	return nil, false
}

func (m *udpSessionManager) closeSession(assocID uint16) {
	if session, ok := m.sessions.LoadAndDelete(assocID); ok {
		s := session.(*udpSession)
		s.cancel()
		close(s.recvChan)
		go m.sendDissociate(assocID)
	}
}

func (m *udpSessionManager) sendDissociate(assocID uint16) {
	stream, err := m.conn.OpenUniStream()
	if err != nil {
		return
	}
	defer stream.Close()
	dissociate := protocol.EncodeDissociate(assocID)
	stream.Write(dissociate)
}

func (m *udpSessionManager) receiveLoop() {
	if m.mode == UDPModeNative {
		go m.receiveDatagrams()
	}
	go m.receiveStreams()
}

func (m *udpSessionManager) receiveDatagrams() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		data, err := m.conn.ReceiveDatagram(m.ctx)
		if err != nil {
			return
		}
		m.handlePacketData(data)
	}
}

func (m *udpSessionManager) receiveStreams() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		stream, err := m.conn.AcceptUniStream(m.ctx)
		if err != nil {
			return
		}
		go m.handleUniStream(stream)
	}
}

func (m *udpSessionManager) handleUniStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)

	header, err := protocol.DecodeHeader(stream)
	if err != nil || header.Type != protocol.CommandPacket {
		return
	}

	pkt, err := protocol.DecodePacketHeader(stream)
	if err != nil {
		return
	}

	data := make([]byte, pkt.Size)
	if _, err := io.ReadFull(stream, data); err != nil {
		return
	}

	m.deliverPacket(pkt.AssocID, pkt.PacketID, pkt.FragTotal, pkt.FragID, data, pkt.Address)
}

func (m *udpSessionManager) handlePacketData(data []byte) {
	if len(data) < 2 {
		return
	}

	header, err := protocol.DecodeHeader(bytes.NewReader(data))
	if err != nil || header.Type != protocol.CommandPacket {
		return
	}

	reader := bytes.NewReader(data[2:])
	pkt, err := protocol.DecodePacketHeader(reader)
	if err != nil {
		return
	}

	remaining := data[len(data)-int(pkt.Size):]
	m.deliverPacket(pkt.AssocID, pkt.PacketID, pkt.FragTotal, pkt.FragID, remaining, pkt.Address)
}

func (m *udpSessionManager) deliverPacket(assocID, packetID uint16, fragTotal, fragID uint8, data []byte, addr protocol.Address) {
	session, ok := m.getSession(assocID)
	if !ok {
		return
	}

	if fragTotal == 1 {
		select {
		case session.recvChan <- &udpPacket{Data: data, Address: addr}:
		default:
		}
		return
	}

	session.handleFragment(packetID, fragTotal, fragID, data, addr)
}

func (s *udpSession) sendPacket(data []byte, addr protocol.Address) error {
	packetID := uint16(s.packetID.Add(1))
	header := protocol.EncodePacket(s.assocID, packetID, 1, 0, uint16(len(data)), addr)
	packet := append(header, data...)

	if s.mgr.mode == UDPModeNative {
		return s.mgr.conn.SendDatagram(packet)
	}

	stream, err := s.mgr.conn.OpenUniStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	_, err = stream.Write(packet)
	return err
}

func (s *udpSession) recvPacket(ctx context.Context) (*udpPacket, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case pkt := <-s.recvChan:
		return pkt, nil
	}
}

func (s *udpSession) handleFragment(packetID uint16, fragTotal, fragID uint8, data []byte, addr protocol.Address) {
	fragMapI, _ := s.fragments.LoadOrStore(packetID, &sync.Map{})
	fragMap := fragMapI.(*sync.Map)
	fragMap.Store(fragID, data)

	// Check if all fragments received
	complete := true
	totalSize := 0
	for i := uint8(0); i < fragTotal; i++ {
		if frag, ok := fragMap.Load(i); ok {
			totalSize += len(frag.([]byte))
		} else {
			complete = false
			break
		}
	}

	if !complete {
		return
	}

	// Reassemble
	assembled := make([]byte, 0, totalSize)
	for i := uint8(0); i < fragTotal; i++ {
		frag, _ := fragMap.Load(i)
		assembled = append(assembled, frag.([]byte)...)
	}
	s.fragments.Delete(packetID)

	select {
	case s.recvChan <- &udpPacket{Data: assembled, Address: addr}:
	default:
	}
}

func (s *udpSession) close() error {
	s.mgr.closeSession(s.assocID)
	return nil
}
