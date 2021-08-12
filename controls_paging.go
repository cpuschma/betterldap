package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ Control = (*PagedResultsControl)(nil)

type PagedResultsControl struct {
	Size   int32
	Cookie []byte
}

func (p *PagedResultsControl) GetControlTyp() string {
	return ControlTypePaging
}

func (p *PagedResultsControl) Marshal() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "pagedResultsControl")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.Size, "size"))

	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "cookie")
	cookie.Value = p.Cookie
	cookie.Data.Write(p.Cookie)
	packet.AppendChild(cookie)

	return createControlRootPacket(ControlTypePaging, false, packet)
}

func (p *PagedResultsControl) Unmarshal(packet *ber.Packet) {
	p.Size = int32(packet.Children[0].Value.(int64))
	p.Cookie = packet.Children[1].Data.Bytes()
}
