package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SimpleBindRequest)(nil)
var _ IBerMessage = (*SimpleBindResult)(nil)

type SimpleBindRequest struct {
	Version  int64
	DN       string
	Password string
}

type SimpleBindResult struct {
	LDAPResult
}

func (s *SimpleBindResult) Builder() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Simple Bind Response")
	s.AddPackets(packet)

	return packet, nil
}

func (s *SimpleBindResult) Decoder(packet *ber.Packet) error {
	return s.LDAPResult.Decoder(packet)
}

func (s *SimpleBindRequest) Builder() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Simple Bind Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.DN, "name"))
	packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, s.Password, "authentication"))

	return packet, nil
}

func (s *SimpleBindRequest) Decoder(packet *ber.Packet) error {
	s.Version = packet.Children[0].Value.(int64)
	s.DN = packet.Children[1].Value.(string)
	s.Password = packet.Children[2].Value.(string)

	return nil
}

func (c *Client) Bind(req *SimpleBindRequest) (*SimpleBindResult, error) {
	packet, err := Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal of bind request failed: %w", err)
	}

	err = c.SendMessage(packet)
	responsePacket, err := c.ReadPacket()
	if err != nil {
		return nil, err
	}

	var simpleBindResult = new(SimpleBindResult)
	simpleBindResult.Decoder(responsePacket)

	return simpleBindResult, nil
}
