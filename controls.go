package betterldap

import (
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type Control interface {
	GetControlType() string
	Marshal() *ber.Packet
	Unmarshal(packet *ber.Packet)
}

func createControlRootPacket(controlType string, criticality bool, op *ber.Packet) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, controlType, "controlType"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, criticality, "criticality"))

	var b []byte
	if op != nil {
		b = op.Bytes()
	}
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(b), "controlValue"))

	return packet
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Marshal())
	}

	return packet
}

func FindControl(controls []Control, controlType string) Control {
	for i := range controls {
		if controls[i].GetControlType() == controlType {
			return controls[i]
		}
	}

	return nil
}

func DecodeControls(controlsEnvelope *ber.Packet) ([]Control, error) {
	if controlsEnvelope == nil {
		return nil, nil
	}

	controls := make([]Control, len(controlsEnvelope.Children))
	for i, packet := range controlsEnvelope.Children {
		control, err := DecodeControl(packet)
		if err != nil {
			return nil, err
		}

		controls[i] = control
	}

	return controls, nil
}

func DecodeControl(packet *ber.Packet) (Control, error) {
	if len(packet.Children) != 2 {
		// required: controlType, controlValue
		return nil, errors.New("missing field in control")
	}

	var (
		controlType = packet.Children[0].Data.String()
		control     Control
	)

	controlValue, err := ber.DecodePacketErr(packet.Children[1].Data.Bytes())
	if err != nil {
		return nil, err
	}

	switch controlType {
	case ControlTypePaging:
		control = &ControlPagedResults{}
		control.Unmarshal(controlValue)
	case ControlTypeAccountUsability:
		control = &ControlAccountUsableResponse{}
		control.Unmarshal(controlValue)
	}

	if control == nil {
		return nil, fmt.Errorf("no control found for type %s", controlType)
	}

	return control, nil
}
