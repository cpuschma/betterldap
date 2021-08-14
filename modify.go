package betterldap

import (
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*ModifyRequest)(nil)
var _ IBerMessage = (*ModifyChanges)(nil)

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
type ModifyRequest struct {
	Object   string
	Changes  []ModifyChanges
	Controls []Control
}

type ModifyChanges struct {
	Operation    ModifyOperation
	Modification PartialAttribute
}

func (m ModifyRequest) Marshal() (messageOp *ber.Packet, controls *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, "ModifyRequest")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.Object, "object"))

	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "changes")
	for _, v := range m.Changes {
		change, _ := v.Marshal()
		changes.AppendChild(change)
	}

	packet.AppendChild(changes)
	return packet, encodeControls(m.Controls)
}

func (m *ModifyRequest) Unmarshal(messageOp *ber.Packet, controls *ber.Packet) error {
	panic("implement me")
}

func (m ModifyChanges) Marshal() (messageOp *ber.Packet, controls *ber.Packet) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "change")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint8(m.Operation), "operation"))

	modification, _ := m.Modification.Marshal()
	packet.AppendChild(modification)

	return packet, nil
}

func (m ModifyChanges) Unmarshal(messageOp *ber.Packet, controls *ber.Packet) error {
	panic("implement me")
}

func (c *Conn) Modify(req ModifyRequest) (result LDAPResult, err error) {
	envelope, handler := c.NewMessage(req.Marshal())
	c.AddHandler(envelope.MessageID, handler)
	defer c.RemoveHandler(envelope.MessageID)

	debug.Log("Sending modify request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		return
	}

	envelope, _ = handler.Receive()
	err = result.Unmarshal(envelope.Packet, envelope.Controls)
	return result, err
}
