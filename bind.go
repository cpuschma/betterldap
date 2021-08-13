package betterldap

import (
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SimpleBindRequest)(nil)

type SimpleBindRequest struct {
	Version  int64
	DN       string
	Password string
}

func (s *SimpleBindRequest) Marshal() (*ber.Packet, *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Simple Bind Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.DN, "name"))
	packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, s.Password, "authentication"))

	return packet, nil
}

func (s *SimpleBindRequest) Unmarshal(packet *ber.Packet, _ *ber.Packet) (err error) {
	s.Version = packet.Children[0].Value.(int64)
	s.DN = packet.Children[1].Data.String()
	s.Password = packet.Children[2].Data.String()

	return nil
}

func (c *Conn) Bind(req SimpleBindRequest) (result SimpleBindResult, err error) {
	envelope, handler := c.NewMessage(req.Marshal())
	c.AddHandler(envelope.MessageID, handler)
	defer c.RemoveHandler(envelope.MessageID)

	debug.Log("Sending bind request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		return
	}

	envelope, _ = handler.Receive()
	err = result.Unmarshal(envelope.Packet, envelope.Controls)
	return
}
