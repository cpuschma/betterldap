package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ IBerMessage = (*UnbindRequest)(nil)

type UnbindRequest struct{}

func (u UnbindRequest) Marshal() (*ber.Packet, error) {
	return ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationUnbindRequest, nil, "unbindRequest"), nil
}

func (u UnbindRequest) Unmarshal(packet *ber.Packet) error {
	return nil
}
