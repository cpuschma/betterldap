package betterldap

import ber "github.com/go-asn1-ber/asn1-ber"

var _ Control = (*ControlAccountUsableResponse)(nil)
var _ Control = (*ControlAccountUsable)(nil)

type ControlAccountUsableResponse struct {
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

type ControlAccountUsable struct{}

func (c ControlAccountUsable) GetControlType() string { return ControlTypeAccountUsability }

func (c ControlAccountUsable) Marshal() *ber.Packet {
	return getControlRootPacket(c.GetControlType(), false, nil)
}

func (c ControlAccountUsable) Unmarshal(_ *ber.Packet) { return }

func (a ControlAccountUsableResponse) GetControlType() string { return ControlTypeAccountUsability }

func (a ControlAccountUsableResponse) Marshal() *ber.Packet {
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

	return getControlRootPacket(a.GetControlType(), false, packet)
}

func (a *ControlAccountUsableResponse) Unmarshal(packet *ber.Packet) {
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
