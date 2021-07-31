package betterldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"strings"
)

type tagMap map[string]string

type IBerMessage interface {
	Builder() (*ber.Packet, error)
	Decoder(*ber.Packet) error
}

func (t tagMap) Get(name string) string {
	val, ok := t[name]
	if !ok {
		return ""
	}

	return val
}

func (t tagMap) Has(name string) bool {
	_, ok := t[name]
	return ok
}

func parseTagValues(tagValue string) (result tagMap) {
	strs := strings.Split(tagValue, ",")
	result = make(map[string]string, len(strs))

	for _, v := range strs {
		name, value, isName := "", "", true
		for _, b := range v {
			if isName {
				if b == '=' {
					isName = false
					continue
				}
				name += string(b)
			} else {
				value += string(b)
			}
		}

		result[name] = value
	}

	return
}

func (t tagMap) getClassOrDefault(d ber.Class) ber.Class {
	v := t.Get("class")
	if v == "" {
		return d
	}

	switch v {
	case "application":
		return ber.ClassApplication
	case "context":
		return ber.ClassContext
	case "private":
		return ber.ClassPrivate
	case "bitmask":
		return ber.ClassBitmask
	case "universal":
		return ber.ClassUniversal
	}

	return d
}

func (t tagMap) getTypeOrDefault(d ber.Type) ber.Type {
	v := t.Get("type")
	if v == "" {
		return d
	}

	switch v {
	case "primitive":
		return ber.TypePrimitive
	case "constructed":
		return ber.TypeConstructed
	case "bitmask":
		return ber.TypeBitmask
	}

	return d
}

func (t tagMap) getTagOrDefault(d ber.Tag) ber.Tag {
	v := t.Get("tag")
	if v == "" {
		return d
	}

	switch v {
	case "eoc":
		return ber.TagEOC
	case "boolean":
		return ber.TagBoolean
	case "integer":
		return ber.TagInteger
	case "bitstring":
		return ber.TagBitString
	case "octetstring":
		return ber.TagOctetString
	case "NULL":
		return ber.TagNULL
	case "objectidentifier":
		return ber.TagObjectIdentifier
	case "objectdescriptor":
		return ber.TagObjectDescriptor
	case "external":
		return ber.TagExternal
	case "realfloat":
		return ber.TagRealFloat
	case "enumerated":
		return ber.TagEnumerated
	case "embeddedPDV":
		return ber.TagEmbeddedPDV
	case "utf8string":
		return ber.TagUTF8String
	case "relativeoid":
		return ber.TagRelativeOID
	case "sequence":
		return ber.TagSequence
	case "set":
		return ber.TagSet
	case "numericstring":
		return ber.TagNumericString
	case "printablestring":
		return ber.TagPrintableString
	case "t61string":
		return ber.TagT61String
	case "videotextstring":
		return ber.TagVideotexString
	case "ia5string":
		return ber.TagIA5String
	case "TagUTCTime":
		return ber.TagUTCTime
	case "generalizedtime":
		return ber.TagGeneralizedTime
	case "graphicalstring":
		return ber.TagGraphicString
	case "visiblestring":
		return ber.TagVisibleString
	case "generalstring":
		return ber.TagGeneralString
	case "universalstring":
		return ber.TagUniversalString
	case "characterstring":
		return ber.TagCharacterString
	case "bmpstring":
		return ber.TagBMPString
	case "bitmask":
		return ber.TagBitmask
	}

	return d
}
