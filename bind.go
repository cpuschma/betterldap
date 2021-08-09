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
	s.DN = packet.Children[1].Data.String()
	s.Password = packet.Children[2].Data.String()

	return nil
}

func (c *Conn) Bind(req *SimpleBindRequest) (*SimpleBindResult, error) {
	packet, _, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal of bind request failed: %w", err)
	}

	envelope, handler := c.NewMessage(packet, nil)
	c.RegisterHandler(envelope.MessageID, handler)
	//defer c.UnregisterHandler(handler)

	debug.Log("Sending bind request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		panic(err)
	}

	envelope, _ = handler.Receive()
	simpleBindResult := &SimpleBindResult{}
	err = simpleBindResult.Unmarshal(envelope.Packet, envelope.Controls)

	return simpleBindResult, err
}
