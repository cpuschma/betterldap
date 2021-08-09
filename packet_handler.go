package betterldap

import (
	"betterldap/internal/debug"
	"bufio"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

func (c *Conn) ReadIncomingMessages() (err error) {
	debug.Log()
	defer func() {
		if e := recover(); err != nil {
			err = fmt.Errorf("message reader panicked: %s", e)
		}
	}()

	buffCon := bufio.NewReaderSize(c.conn, 4096)
	for {
		if c.isClosing {
			return
		}

		var packet *ber.Packet
		packet, err = ber.ReadPacket(buffCon)
		if err != nil {
			if c.isClosing {
				err = nil // disregard
			}

			return
		}

		envelope := c.CreateEnvelopeFromPacket(packet)
		debug.Logf("Incoming msg (messageID=%d)", envelope.MessageID)

		handler := c.FindHandler(envelope.MessageID)
		if handler == nil {
			debug.Logf("No handler registered for message with id=%d (%#v)", envelope.MessageID, envelope)
			if c.defaultHandler != nil {
				c.defaultHandler(c, envelope)
			}

			continue
		}

		handler.Send(envelope)
	}
}

type Handler struct {
	c chan *Envelope
}

func NewHandler() *Handler {
	return &Handler{
		c: make(chan *Envelope, 3),
	}
}

func (m *Handler) Close() {
	close(m.c)
}

func (m *Handler) Send(e *Envelope) {
	m.c <- e
}

func (m *Handler) Receive() (*Envelope, bool) {
	val, ok := <-m.c
	return val, ok
}
