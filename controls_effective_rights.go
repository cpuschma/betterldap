package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ Control = (*ControlGetRights)(nil)

// https://ldapwiki.com/wiki/Get%20Effective%20Rights%20Control
type ControlGetRights struct {
	AuthzID    string // https://ldapwiki.com/wiki/LDAP%20authzid%20prefixes
	Attributes []string
}

func (c ControlGetRights) GetControlType() string { return ControlTypeGetRights }

func (c ControlGetRights) Marshal() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "GetRightsControl")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.AuthzID, "authzID"))

	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, v := range c.Attributes {
		attribute := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "attribute")
		seq.AppendChild(attribute)
	}

	packet.AppendChild(seq)
	return getControlRootPacket(c.GetControlType(), false, packet)
}

func (c ControlGetRights) Unmarshal(packet *ber.Packet) {
	panic("implement me")
}
