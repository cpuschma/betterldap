package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ IBerMessage = (*UnbindRequest)(nil)

type UnbindRequest struct{}

func (u UnbindRequest) Marshal() (*ber.Packet, *ber.Packet, error) {
	return ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationUnbindRequest, nil, "unbindRequest"), nil, nil
}

func (u UnbindRequest) Unmarshal(messageOp *ber.Packet, controls *ber.Packet) error {
	return nil
}
