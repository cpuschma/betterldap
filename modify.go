package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ IBerMessage = (*ModifyRequest)(nil)

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
type ModifyRequest struct {
}

func (m ModifyRequest) Marshal() (messageOp *ber.Packet, controls *ber.Packet) {
	panic("implement me")
}

func (m ModifyRequest) Unmarshal(messageOp *ber.Packet, controls *ber.Packet) error {
	panic("implement me")
}
