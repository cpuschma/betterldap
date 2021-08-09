package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ IBerMessage = (*Controls)(nil)

type Control IBerMessage
type Controls []Control

func (c Controls) Marshal() (_ *ber.Packet, controls *ber.Packet) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for i := range c {
		_, control := c[i].Marshal()
		packet.AppendChild(control)
	}

	return nil, packet
}

func (c Controls) Unmarshal(_ *ber.Packet, controls *ber.Packet) error {
	return nil
}

func FindControls(packet *ber.Packet) []Control {
	return nil
}
