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

	return packet.Children[1], nil // Skip MessageID
}

// EncapsulatePacket
func (c *Client) EncapsulatePacket(packet *ber.Packet) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.getNextMessageID(), "MessageID"))
	envelope.AppendChild(packet)

	return envelope
}

// getNextMessageID
func (c *Client) getNextMessageID() (i int32) {
	c.mu.Lock()
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
