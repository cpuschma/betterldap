package betterldap

import (
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type Envelope struct {
	MessageID int32
	Packet    *ber.Packet
	Controls  *ber.Packet
}

func (m *Envelope) Marshal() *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, m.MessageID, "MessageID"))
	envelope.AppendChild(m.Packet) // protocolOp

	// TODO: Implement controls

	return envelope
}

func (m *Envelope) Unmarshal(packet *ber.Packet) error {
	childrenCount := len(packet.Children)
	if childrenCount < 2 {
		return errors.New("envelope has less than two child packets")
	}

	var i int64
	if err := parseInt64(packet, 0, &i); err != nil {
		return fmt.Errorf("%w: missing or incorrect messageID in envelope", err)
	}

	m.MessageID = int32(i)
	m.Packet = packet.Children[1]
	if childrenCount > 2 {
		m.Controls = packet.Children[2]
	}

	return nil
}
