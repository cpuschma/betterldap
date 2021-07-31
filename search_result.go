package betterldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SearchResult)(nil)
var _ IBerMessage = (*Entry)(nil)
var _ IBerMessage = (*PartialAttributeList)(nil)
var _ IBerMessage = (*SearchResultDone)(nil)

type SearchResult struct {
	Entries []*Entry
	//Referrals []string
	//Controls []Control

	LDAPResult
}

type SearchResultDone struct {
	LDAPResult
}

func (s *SearchResult) Builder() (*ber.Packet, error) {
	return nil, nil
}

func (s *SearchResult) Decoder(packet *ber.Packet) error {
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
//	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//		objectName      LDAPDN,
//		attributes      PartialAttributeList }
//
//	PartialAttributeList ::= SEQUENCE OF
//		partialAttribute PartialAttribute
//
//	PartialAttribute ::= SEQUENCE {
//		type       AttributeDescription,
//		vals       SET OF value AttributeValue }
//
//	SearchResultReference ::= [APPLICATION 19] SEQUENCE
//		SIZE (1..MAX) OF uri URI
//
//	SearchResultDone ::= [APPLICATION 5] LDAPResult

type Entry struct {
	DN         string
	Attributes []*PartialAttributeList
}

func (e Entry) Builder() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagOctetString, nil, "searchResultEntry")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	// TODO: Append attributes
	packet.AppendChild(attributes)

	return packet, nil
}

func (e Entry) Decoder(packet *ber.Packet) error {
	panic("implement me")
}

///////////////////////////////////////////////////////

type PartialAttributeList struct {
	Name   string
	Values []string
}

func (e *PartialAttributeList) Builder() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "partialAttributeList")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.Name, "type"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, v := range e.Values {
		attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
	}
	packet.AppendChild(attributes)

	return nil, nil
}

func (e *PartialAttributeList) Decoder(packet *ber.Packet) error {
	e.Name = packet.Children[0].Value.(string) // Name
	// Pre-allocate, since we can determine the length at this point
	e.Values = make([]string, len(packet.Children[1].Children))

	for i, v := range packet.Children[1].Children { // Values
		e.Values[i] = v.Value.(string)
	}

	return nil
}
