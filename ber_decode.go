package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
	"reflect"
)

func Unmarshal(packet *ber.Packet, dst interface{}) (err error) {
	targetStruct := reflect.ValueOf(dst)
	if targetStruct.Kind() != reflect.Ptr || targetStruct.IsNil() {
		return fmt.Errorf("cannot unmarshal packet. expected pointer to struct, got %v", dst)
	}

	if dst, ok := dst.(IBerMessage); ok {
		return dst.Decoder(packet)
	}

	targetStruct = targetStruct.Elem()
	for i := 0; i < targetStruct.Type().NumField(); i++ {
		targetType := targetStruct.Type().Field(i)
		if targetType.Tag.Get("ber") == "-" {
			continue
		}
		targetValue := targetStruct.Field(i)
		tagValues := parseTagValues(targetType.Tag.Get("ber"))

		if targetType.Type.Kind() == reflect.Struct {
			if err = Unmarshal(packet.Children[i], targetValue.Interface()); err != nil {
				return err
			}
		} else {
			if err = decodePrimitiveType(targetValue, packet.Children[i], tagValues); err != nil {
				return err
			}
		}
	}

	return
}

func decodePrimitiveType(fieldValue reflect.Value, packet *ber.Packet, tagValues tagMap) error {
	if tagValues.Has("placeholder") {
		return nil
	}

	switch fieldValue.Interface().(type) {
	case []string:
		strArray := make([]string, len(packet.Children))
		for i, children := range packet.Children {
			val, ok := children.Value.(string)
			if !ok {
				return fmt.Errorf("cast of string value failed. expected string, got %v", packet.Value)
			}

			strArray[i] = val
		}
		fieldValue.Set(reflect.ValueOf(strArray))

		break
	case string:
		val, ok := packet.Value.(string)
		if !ok {
			return fmt.Errorf("cast of string value failed. expected string, got %v", packet.Value)
		}

		fieldValue.SetString(val)
		break
	case uint:
	case uint8:
	case uint16:
	case uint32:
	case uint64:
		val, ok := packet.Value.(uint64)
		if !ok {
			return fmt.Errorf("cast of uint64 value failed. expected uintX, got %v", packet.Value)
		}

		fieldValue.SetUint(val)
		break
	case int:
	case int8:
	case int16:
	case int32:
	case int64:
		val, ok := packet.Value.(uint64)
		if !ok {
			return fmt.Errorf("cast of int64 value failed. expected intX, got %v", packet.Value)
		}

		fieldValue.SetInt(int64(val))
		break
	case bool:
		val, ok := packet.Value.(bool)
		if !ok {
			return fmt.Errorf("cast of bool value failed. expected bool, got %v", packet.Value)
		}

		fieldValue.SetBool(val)
		break
	}

	return nil
}
