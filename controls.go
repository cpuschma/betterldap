package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

type Control interface {
}

func FindControls(packet *ber.Packet) []Control {
	return nil
}
