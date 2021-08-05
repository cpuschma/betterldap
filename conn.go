package betterldap

import (
	"betterldap/internal/debug"
	"fmt"
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
	activeMessages    map[int32]*Handler
	closeMsgProcessor chan struct{}
}

func NewConnection(conn net.Conn) *Conn {
	return &Conn{
		conn:              conn,
		mu:                &sync.RWMutex{},
		closeMsgProcessor: make(chan struct{}, 1),
		activeMessages:    make(map[int32]*Handler),
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.Write(b)
}

// Close will tell the underyling connection to close
// and close all associated channels
func (c *Conn) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.once.Do(func() {
		err = c.conn.Close()
		close(c.closeMsgProcessor)
	})

	return
}

// SendMessage is a wrapper for Conn.Write. It further
// puts the *ber.Packet into an envelope using
// NewEnvelope and marshal's it into binary.
func (c *Conn) SendMessage(packet *ber.Packet) error {
	_, err := c.Write(packet.Bytes())
	return err
}

func (c *Conn) ReadPacket() (*ber.Packet, error) {
	return ber.ReadPacket(c.conn)
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

func (c *Conn) UnpackEnvelope(packet *ber.Packet) *Envelope {
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

func (c *Conn) ReadIncomingMessages() (err error) {
	debug.Log("")
	c.wg.Add(1)
	defer func() {
		debug.Log("exited")
		if err := recover(); err != nil {
			err = fmt.Errorf("ldap message processor panicked: %v", err)
		}

		// Since the reader dies here, there's no other process
		// reading incoming messages, so we should kill the connection
		// at this point
		err = c.Close()
	}()

	debug.Log("Looping and waiting for incoming packets")
	for {
		select {
		case <-c.closeMsgProcessor:
			debug.Logf("closeMsgProcessor chan is closed, ending routine now")
			break
		default:
			var incomingPacket *ber.Packet
			incomingPacket, err = c.ReadPacket()
			if err != nil {
				return
			}

			envelope := &Envelope{}
			err = envelope.Unmarshal(incomingPacket)
			if err != nil {
				return
			}

			handler := c.FindMessageHandler(envelope.MessageID)
			if handler == nil {
				// disregard this message, no handler for this id registered
				continue
			}

			handler.receiverChan <- envelope
			break
		}
	}
}

func (c *Conn) RegisterMessage(m *Handler) {
	c.mu.Lock()
	c.activeMessages[m.messageID] = m
	c.mu.Unlock()
	debug.Logf("(messageID=%d)", m.messageID)
}

func (c *Conn) FindMessageHandler(id int32) *Handler {
	c.mu.RLock()
	defer c.mu.RUnlock()

	msg, ok := c.activeMessages[id]
	if !ok {
		return nil
	}
	return msg
}

func (c *Conn) UnregisterMessage(m *Handler) {
	c.mu.Lock()
	delete(c.activeMessages, m.messageID)
	c.mu.Unlock()
	m.Close()
	debug.Logf("(messageID=%d)", m.messageID)
}

func (c *Conn) newMessage(op, control *ber.Packet) (*Envelope, *Handler) {
	envelope := c.NewEnvelope(op, control)
	debug.Logf("-> envelope.MessageID=%d", envelope.MessageID)

	return envelope, NewMessage(envelope.MessageID)
}