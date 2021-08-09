package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*LDAPResult)(nil)

type LDAPResult struct {
	ResultCode   int64
	MatchedDN    string
	ErrorMessage string
}

func isLDAPResult(packet *ber.Packet) bool {
	if packet.ClassType == ber.ClassApplication &&
		packet.TagType == ber.TypeConstructed &&
		len(packet.Children) == 3 {
		return true
	}

	return false
}

func (l *LDAPResult) Error() string {
	return fmt.Sprintf("%d: %s", l.ResultCode, l.ErrorMessage)
}

func (l *LDAPResult) Packets() []*ber.Packet {
	packets := make([]*ber.Packet, 3)
	packets[0] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, l.ResultCode, "ResultCode")
	packets[1] = ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, l.MatchedDN, "MatchedDN")
	packets[2] = ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, l.ErrorMessage, "errorMessage")

	return packets
}

func (l *LDAPResult) AddPackets(parent *ber.Packet) {
	for _, p := range l.Packets() {
		parent.AppendChild(p)
	}
}

func (l *LDAPResult) Marshal() (*ber.Packet, *ber.Packet) {
	return nil, nil
}

func (l *LDAPResult) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
	l.ResultCode = packet.Children[0].Value.(int64)
	l.MatchedDN = packet.Children[1].Value.(string)
	l.ErrorMessage = packet.Children[2].Value.(string)

	return nil
}
