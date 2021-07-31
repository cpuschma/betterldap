package betterldap

import (
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
	"reflect"
)

// Marshal is an experimental function for automatically encoding
// Golang structs to ASN1 BER packets. It heavily utilizes reflect
// and struct field tags to identify the right ASN1 BER class, type and tag
//
// As the underlying asn1-ber library makes it nearly impossible / inefficient
// to set placeholder values, the method is not used very much throughout
// the project, due to cases where the field needs special handling
// e.g. the Filter in ApplicationSearchRequest ...
func Marshal(src interface{}, forceNativeBuilder ...bool) (packet *ber.Packet, err error) {
	if src, ok := src.(IBerMessage); ok {
		return src.Builder()
	} else {
		packet = ber.Encode(
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSequence,
			nil,
			"",
		)
	}

	fieldsType := reflect.TypeOf(src)
	fieldsValue := reflect.ValueOf(src)

	if fieldsType.Kind() == reflect.Ptr {
		fieldsType = fieldsType.Elem()
		fieldsValue = reflect.ValueOf(src).Elem()
	}

	for i := 0; i < fieldsValue.NumField(); i++ {
		tagValue := fieldsType.Field(i).Tag.Get("ber")
		if tagValue == "-" {
			continue
		}

		var (
			fieldValue = fieldsValue.Field(i)
			child      = &ber.Packet{}
			tagValues  = parseTagValues(tagValue)
			fieldName  = fieldsType.Field(i).Name
		)

		debug.Logf("Marshal struct field '%s'", fieldName)
		if fieldValue.Kind().String() == "struct" {
			child, err = Marshal(fieldValue.Interface())
			if err != nil {
				return nil, err
			}
		} else {
			child = encodePrimitiveType(fieldValue, tagValues)
		}

		if child == nil {
			continue
		}

		packet.AppendChild(child)
		debug.Logf("Packet: %#v\n", packet)
	}

	return packet, nil
}

func encodePrimitiveType(fieldValue reflect.Value, tagValues tagMap) (child *ber.Packet) {
	if tagValues.Has("placeholder") {
		return nil
	}

	switch fieldValue.Interface().(type) {
	case []string:
		child = ber.Encode(
			tagValues.getClassOrDefault(ber.ClassUniversal),
			tagValues.getTypeOrDefault(ber.TypeConstructed),
			tagValues.getTagOrDefault(ber.TagSequence), nil, tagValues.Get("description"))
		for _, v := range fieldValue.Interface().([]string) {
			child.AppendChild(
				ber.NewString(
					ber.ClassUniversal,
					ber.TypePrimitive,
					ber.TagOctetString,
					v,
					"",
				),
			)
		}

		debug.Logf("New child of type []string: %#v\n", child)
		break
	case string:
		child = ber.NewString(
			tagValues.getClassOrDefault(ber.ClassUniversal),
			tagValues.getTypeOrDefault(ber.TypePrimitive),
			tagValues.getTagOrDefault(ber.TagOctetString),
			fieldValue.String(),
			tagValues.Get("description"),
		)
		debug.Logf("New child of type string: %#v\n", child)
		break
	case uint:
	case uint8:
	case uint16:
	case uint32:
	case uint64:
		child = ber.NewInteger(
			tagValues.getClassOrDefault(ber.ClassUniversal),
			tagValues.getTypeOrDefault(ber.TypePrimitive),
			tagValues.getTagOrDefault(ber.TagInteger),
			fieldValue.Uint(),
			tagValues.Get("description"),
		)
		debug.Logf("New child of type unsigned integer: %#v\n", child)

		break
	case int:
	case int8:
	case int16:
	case int32:
	case int64:
		child = ber.NewInteger(
			tagValues.getClassOrDefault(ber.ClassUniversal),
			tagValues.getTypeOrDefault(ber.TypePrimitive),
			tagValues.getTagOrDefault(ber.TagInteger),
			fieldValue.Int(),
			tagValues.Get("description"),
		)
		debug.Logf("New child of type integer: %#v\n", child)
		break
	case bool:
		child = ber.NewBoolean(
			tagValues.getClassOrDefault(ber.ClassUniversal),
			tagValues.getTypeOrDefault(ber.TypePrimitive),
			tagValues.getTagOrDefault(ber.TagBoolean),
			fieldValue.Bool(),
			tagValues.Get("description"),
		)
		debug.Logf("New child of type bool: %#v\n", child)

		break
	}

	return
}
