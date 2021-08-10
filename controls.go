package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type Control interface {
	Marshal() *ber.Packet
	Unmarshal(packet *ber.Packet)
}

func createControlRootPacket(controlType string, criticality bool, op *ber.Packet) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, controlType, "controlType"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, criticality, "criticality"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(op.Bytes()), "controlValue"))

	return packet
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Marshal())
	}

	return packet
}

func DecodeControls(packets []*ber.Packet) ([]Control, error) {
	controls := make([]Control, len(packets))
	for i, packet := range packets {
		control, err := FindControl(packet)
		if err != nil {
			return nil, err
		}

		controls[i] = control
	}

	return controls, nil
}

func FindControl(packet *ber.Packet) (Control, error) {
	var (
		controlType  = packet.Children[0].Data.String()
		control      Control
		controlValue *ber.Packet
	)

	if packet.Children[2] != nil {
		var err error
		controlValue, err = ber.DecodePacketErr(packet.Children[2].Data.Bytes())
		if err != nil {
			return nil, err
		}
	}

	switch controlType {
	case ControlTypePaging:
		control = &PagedResultsControl{}
		control.Unmarshal(controlValue)
		break
	}

	if control == nil {
		return nil, fmt.Errorf("no control found for type %s", controlType)
	}

	return control, nil
}

//

var _ Control = (*PagedResultsControl)(nil)

type PagedResultsControl struct {
	Size   int32
	Cookie []byte
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
