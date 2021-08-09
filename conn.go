package betterldap

import (
	"betterldap/internal/debug"
	"context"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
	"sync"
	"time"
)

type Conn struct {
	conn              net.Conn
	mu                *sync.RWMutex
	wg                sync.WaitGroup
	once              sync.Once
	messageID         int32
	activeHandlers    map[int32]chan *Envelope
	closeMsgProcessor chan struct{}
	receiverChan      chan *ber.Packet
	isClosing         bool
	defaultHandler    func(*Conn, *Envelope)
	context.Context
}

func NewConnection(conn net.Conn) *Conn {
	return &Conn{
		conn:              conn,
		mu:                &sync.RWMutex{},
		closeMsgProcessor: make(chan struct{}, 1),
		receiverChan:      make(chan *ber.Packet, 12),
		activeHandlers:    make(map[int32]chan *Envelope),
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	n, err := c.conn.Write(b)
	c.mu.Unlock()
	return n, err
}

// Close will tell the underyling connection to close
// and close all associated channels
func (c *Conn) Close() (err error) {
	c.once.Do(func() {
		c.isClosing = true
		close(c.closeMsgProcessor)
		err = c.conn.Close()
		c.wg.Wait()
	})
	return
}

func (c *Conn) IsClosing() bool {
	return c.isClosing
}

// SendMessage is a wrapper for Conn.Write. It further
// puts the *ber.Packet into an envelope using
// NewEnvelope and marshal's it into binary.
func (c *Conn) SendMessage(packet *ber.Packet) error {
	_, err := c.Write(packet.Bytes())
	return err
}

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
//	LDAPMessage ::= SEQUENCE {
//		messageID       MessageID,
//		protocolOp      CHOICE {
//		bindRequest           BindRequest,
//		bindResponse          BindResponse,
//		unbindRequest         UnbindRequest,
//		searchRequest         SearchRequest,
//		searchResEntry        SearchResultEntry,
//		searchResDone         SearchResultDone,
//		searchResRef          SearchResultReference,
//		modifyRequest         ModifyRequest,
//		modifyResponse        ModifyResponse,
//		addRequest            AddRequest,
//		addResponse           AddResponse,
//		delRequest            DelRequest,
//		delResponse           DelResponse,
//		modDNRequest          ModifyDNRequest,
//		modDNResponse         ModifyDNResponse,
//		compareRequest        CompareRequest,
//		compareResponse       CompareResponse,
//		abandonRequest        AbandonRequest,
//		extendedReq           ExtendedRequest,
//		extendedResp          ExtendedResponse,
//		...,
//		intermediateResponse  IntermediateResponse },
//		controls       [0] Controls OPTIONAL }

// NewEnvelope
func (c *Conn) NewEnvelope(op, controls *ber.Packet) *Envelope {
	envelope := &Envelope{
		MessageID: c.getNextMessageID(),
		Packet:    op,
		Controls:  controls,
	}

	return envelope
}

func (c *Conn) CreateEnvelopeFromPacket(packet *ber.Packet) *Envelope {
	envelope := &Envelope{
		MessageID: int32(packet.Children[0].Value.(int64)),
		Packet:    packet.Children[1],
		Controls:  nil,
	}

	return envelope
}

// getNextMessageID
func (c *Conn) getNextMessageID() (i int32) {
	c.mu.Lock()
	// It really doesn't matter if we overflow this integer.
	// If ONE client really exceeds 2.147.483.647 active messages
	// then overflowing one integer is probably your least problem..
	// See: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
	c.messageID++
	i = c.messageID
	c.mu.Unlock()
	return
}

// SetDeadline is a wrapper for net.Conn.SetDeadline
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetDeadline(t)
}

// SetReadDeadline is a wrapper for net.Conn.SetReadDeadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline is a wrapper for net.Conn.SetWriteDeadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) RegisterHandler(id int32, m chan *Envelope) {
	c.mu.Lock()
	c.activeHandlers[id] = m
	c.mu.Unlock()
	debug.Logf("(messageID=%d)", id)
}

func (c *Conn) FindMessageHandler(id int32) chan *Envelope {
	c.mu.RLock()
	defer c.mu.RUnlock()

	channel, ok := c.activeHandlers[id]
	if !ok {
		return nil
	}
	return channel
}

func (c *Conn) UnregisterHandler(id int32, m Handler) {
	c.mu.Lock()
	delete(c.activeHandlers, id)
	c.mu.Unlock()
	m.Close()
	debug.Logf("(messageID=%d)", id)
}

func (c *Conn) NewMessage(op, control *ber.Packet) (*Envelope, Handler) {
	envelope := c.NewEnvelope(op, control)
	debug.Logf("-> envelope.MessageID=%d", envelope.MessageID)

	return envelope, NewHandler()
}
