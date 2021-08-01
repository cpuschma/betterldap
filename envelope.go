package betterldap

import (
	"errors"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*Message)(nil)

type Message struct {
	MessageID int32
	Packet    *ber.Packet
	Controls  interface{} // TODO!
}

func (m *Message) Marshal() (*ber.Packet, error) {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, m.MessageID, "MessageID"))
	envelope.AppendChild(m.Packet) // protocolOp

	return envelope, nil
}

func (m *Message) Unmarshal(packet *ber.Packet) error {
	childrenCount := len(packet.Children)
	if childrenCount < 2 {
		return errors.New("envelope has less than two child packets")
	}

	m.MessageID = int32(packet.Children[0].Value.(int64))
	m.Packet = packet.Children[1]

	if childrenCount > 2 {
		// TODO: Implement controls
	}

	return nil
}
