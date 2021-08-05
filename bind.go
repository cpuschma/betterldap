package betterldap

import (
	"betterldap/internal/debug"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SimpleBindRequest)(nil)

type SimpleBindRequest struct {
	Version  int64
	DN       string
	Password string
}

func (s *SimpleBindRequest) Marshal() (*ber.Packet, *ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Simple Bind Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.DN, "name"))
	packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, s.Password, "authentication"))

	return packet, nil, nil
}

func (s *SimpleBindRequest) Unmarshal(packet *ber.Packet, _ *ber.Packet) (err error) {
	s.Version = packet.Children[0].Value.(int64)
	if err = parseString(packet, 1, &s.DN); err != nil {
		return
	}
	if err = parseString(packet, 2, &s.Password); err != nil {
		return
	}

	return nil
}

func (c *Conn) Bind(req *SimpleBindRequest) (*SimpleBindResult, error) {
	packet, _, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal of bind request failed: %w", err)
	}

	envelope, handler := c.newMessage(packet, nil)
	c.RegisterMessage(handler)
	defer c.UnregisterMessage(handler)

	debug.Log("Sending bind request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		panic(err)
	}

	envelope, err = handler.Receive()
	simpleBindResult := &SimpleBindResult{}
	err = simpleBindResult.Unmarshal(envelope.Packet, envelope.Controls)

	return simpleBindResult, err
}
