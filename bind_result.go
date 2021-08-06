package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ IBerMessage = (*SimpleBindResult)(nil)

type SimpleBindResult struct {
	LDAPResult
}

func (s *SimpleBindResult) Marshal() (*ber.Packet, *ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Simple Bind Response")
	s.LDAPResult.AddPackets(packet)

	return packet, nil, nil
}

func (s *SimpleBindResult) Unmarshal(packet *ber.Packet, control *ber.Packet) error {
	return s.LDAPResult.Unmarshal(packet, control)
}
