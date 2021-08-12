package betterldap

import (
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*DeleteRequest)(nil)

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
type DeleteRequest struct {
	DN string
}

func (d *DeleteRequest) Marshal() (messageOp *ber.Packet, controls *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "DelRequest")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, d.DN, "LDAPDN"))

	return packet, nil
}

func (d *DeleteRequest) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
	d.DN = packet.Children[0].Data.String()
	return nil
}

func (c *Conn) Delete(req *DeleteRequest) (result LDAPResult, err error) {
	envelope, handler := c.NewMessage(req.Marshal())
	c.AddHandler(envelope.MessageID, handler)
	defer c.RemoveHandler(envelope.MessageID)

	debug.Log("Sending delete request")
	err = c.SendMessage(envelope.Marshal())
	if err != nil {
		return
	}

	envelope, _ = handler.Receive()
	err = result.Unmarshal(envelope.Packet, envelope.Controls)
	return result, err
}
