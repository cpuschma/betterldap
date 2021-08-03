package betterldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

type IBerMessage interface {
	Marshal() (messageOp *ber.Packet, controls *ber.Packet, err error)
	Unmarshal(messageOp *ber.Packet, controls *ber.Packet) error
}
