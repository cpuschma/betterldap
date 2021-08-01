package betterldap

import (
	"crypto/tls"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
	"sync"
	"time"
)

type Client struct {
	conn      net.Conn
	mu        *sync.RWMutex
	wg        sync.WaitGroup
	messageID int32
}

type ConnectionOptions struct {
	TLSConfig *tls.Config
	Dialer    net.Dialer
}

func Dial(network, address string, opt ConnectionOptions) (*Client, error) {
	conn, err := opt.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return NewConnection(conn), nil
}

func DialTLS(network, address string, opt ConnectionOptions) (*Client, error) {
	conn, err := tls.DialWithDialer(
		&opt.Dialer,
		network,
		address,
		opt.TLSConfig,
	)
	if err != nil {
		return nil, err
	}

	return NewConnection(conn), nil
}

func NewConnection(conn net.Conn) *Client {
	return &Client{
		conn: conn,
		mu:   &sync.RWMutex{},
	}
}

func (c *Client) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.Write(b)
}

// Close will tell the underyling connection to close
// and close all associated channels
func (c *Client) Close() error {
	return c.conn.Close()
}

// SendMessage is a wrapper for Client.Write. It further
// puts the *ber.Packet into an envelope using
// EncapsulatePacket and marshal's it into binary.
func (c *Client) SendMessage(packet *ber.Packet) error {
	packet = c.EncapsulatePacket(packet)
	_, err := c.Write(packet.Bytes())
	return err
}

func (c *Client) ReadPacket() (*ber.Packet, error) {
	packet, err := ber.ReadPacket(c.conn)
	if err != nil {
		return nil, err
	}

	packet.Children[0].Description = "MessageID"
	return packet, nil
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

// EncapsulatePacket
func (c *Client) EncapsulatePacket(packet *ber.Packet) *ber.Packet {
	envelope := &Message{
		MessageID: c.getNextMessageID(),
		Packet:    packet,
		Controls:  nil,
	}

	p, _ := envelope.Marshal()
	return p
}

// getNextMessageID
func (c *Client) getNextMessageID() (i int32) {
	c.mu.Lock()
	// It doesn't really matter if we overflow this integer.
	// If ONE client really exceeds 2.147.483.647 active messages
	// then overflowing one integer is probably your least problem..
	// See: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
	c.messageID++
	i = c.messageID
	c.mu.Unlock()
	return
}

// SetDeadline is a wrapper for net.Conn.SetDeadline
func (c *Client) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetDeadline(t)
}

// SetReadDeadline is a wrapper for net.Conn.SetReadDeadline
func (c *Client) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline is a wrapper for net.Conn.SetWriteDeadline
func (c *Client) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.SetWriteDeadline(t)
}
