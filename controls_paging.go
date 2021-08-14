package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ Control = (*ControlPagedResults)(nil)

type ControlPagedResults struct {
	Size   int32
	Cookie []byte
}

func (p *ControlPagedResults) GetControlType() string {
	return ControlTypePaging
}

func (p *ControlPagedResults) Marshal() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "pagedResultsControl")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.Size, "size"))

	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "cookie")
	cookie.Value = p.Cookie
	cookie.Data.Write(p.Cookie)
	packet.AppendChild(cookie)

	return getControlRootPacket(p.GetControlType(), false, packet)
}

func (p *ControlPagedResults) Unmarshal(packet *ber.Packet) {
	p.Size = int32(packet.Children[0].Value.(int64))
	p.Cookie = packet.Children[1].Data.Bytes()
}
