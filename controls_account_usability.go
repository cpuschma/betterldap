package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ Control = (*AccountUsableResponse)(nil)

type AccountUsableResponse struct {
	IsAvailable    int32
	IsNotAvailable *AccountUsableResponseInfo
}

type AccountUsableResponseInfo struct {
	Inactive            bool
	Reset               bool
	Expired             bool
	RemainingGrace      int32
	SecondsBeforeUnlock int32
}

func (a AccountUsableResponse) GetControlTyp() string { return ControlTypeAccountUsability }

func (a *AccountUsableResponse) Marshal() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "accountUsableResponse")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, a.IsAvailable, "is_available"))

	if a.IsNotAvailable != nil {
		infoPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "more_info")
		infoPacket.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, a.IsNotAvailable.Inactive, "inactive"))
		infoPacket.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, a.IsNotAvailable.Reset, "reset"))
		infoPacket.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, a.IsNotAvailable.Expired, "expired"))
		infoPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, a.IsNotAvailable.RemainingGrace, "remaining_grace"))
		infoPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, a.IsNotAvailable.SecondsBeforeUnlock, "seconds_before_unlock"))

		packet.AppendChild(infoPacket)
	}

	return createControlRootPacket(ControlTypeAccountUsability, false, packet)
}

func (a *AccountUsableResponse) Unmarshal(packet *ber.Packet) {
	a.IsAvailable = int32(packet.Children[0].Value.(int64))

	// is 'is_not_available' sequence present?
	if len(packet.Children) > 1 {
		info := packet.Children[1]
		a.IsNotAvailable = &AccountUsableResponseInfo{
			Inactive: info.Children[0].Value.(bool),
			Reset:    info.Children[1].Value.(bool),
			Expired:  info.Children[2].Value.(bool),
		}

		// Both remaining_grace and seconds_before_unlock are optional
		if len(info.Children) > 3 {
			a.IsNotAvailable.RemainingGrace = int32(info.Children[3].Value.(int64))
			if len(info.Children) > 4 {
				a.IsNotAvailable.SecondsBeforeUnlock = int32(info.Children[4].Value.(int64))
			}
		}
	}
}
