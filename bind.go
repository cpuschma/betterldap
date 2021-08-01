package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SimpleBindRequest)(nil)

type SimpleBindRequest struct {
	Version  int64
	DN       string
	Password string
}

func (s *SimpleBindRequest) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Simple Bind Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.DN, "name"))
	packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, s.Password, "authentication"))

	return packet, nil
}

func (s *SimpleBindRequest) Unmarshal(packet *ber.Packet) error {
	packet = packet.Children[1] // Skip MessageID

	s.Version = packet.Children[0].Value.(int64)
	s.DN = packet.Children[1].Value.(string)
	s.Password = packet.Children[2].Value.(string)

	return nil
}

func (c *Client) Bind(req *SimpleBindRequest) (*SimpleBindResult, error) {
	packet, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal of bind request failed: %w", err)
	}

	err = c.SendMessage(packet)
	packet, err = c.ReadPacket()
	if err != nil {
		return nil, err
	}

	simpleBindResult := &SimpleBindResult{}
	err = simpleBindResult.Unmarshal(packet)

	return simpleBindResult, err
}

///////////////////////////////////////////////////

var _ IBerMessage = (*SimpleBindResult)(nil)

type SimpleBindResult struct {
	LDAPResult
}

func (s *SimpleBindResult) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Simple Bind Response")
	s.AddPackets(packet)

	return packet, nil
}

func (s *SimpleBindResult) Unmarshal(packet *ber.Packet) error {
	return s.LDAPResult.Unmarshal(packet)
}
