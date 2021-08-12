package betterldap

import (
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*AddRequest)(nil)

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
type AddRequest struct {
	DN         string
	Attributes []PartialAttribute
}

func (a *AddRequest) Marshal() (messageOp *ber.Packet, controls *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "AddRequest")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.DN, "entry"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, v := range a.Attributes {
		child, _ := v.Marshal()
		attributes.AppendChild(child)
	}
	packet.AppendChild(attributes)

	return packet, nil
}

func (a *AddRequest) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
	a.DN = packet.Children[0].Data.String()

	a.Attributes = make([]PartialAttribute, len(packet.Children[1].Children))
	for i := range a.Attributes {
		if err := a.Attributes[i].Unmarshal(packet.Children[1].Children[i], nil); err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) Add(request AddRequest) (result LDAPResult, err error) {
	envelope, handler := c.NewMessage(request.Marshal())
	c.AddHandler(envelope.MessageID, handler)
	defer c.RemoveHandler(envelope.MessageID)

	debug.Log("Sending Add request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		return
	}

	envelope, _ = handler.Receive()
	err = result.Unmarshal(envelope.Packet, envelope.Controls)
	return result, err
}
