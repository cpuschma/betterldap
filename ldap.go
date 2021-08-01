package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

type IBerMessage interface {
	Marshal() (*ber.Packet, error)
	Unmarshal(*ber.Packet) error
}
