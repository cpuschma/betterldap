package betterldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SearchResult)(nil)

type SearchResult struct {
	Entries []*SearchResultEntry
	//Referrals []string
	//Controls []Control

	LDAPResult
}

func (s *SearchResult) Marshal() (*ber.Packet, error) {
	return nil, nil
}

func (s *SearchResult) Unmarshal(packet *ber.Packet) error {
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

var _ IBerMessage = (*SearchResultEntry)(nil)

type SearchResultEntry struct {
	DN         string
	Attributes []*PartialAttributeList
}

func (e *SearchResultEntry) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagOctetString, nil, "searchResultEntry")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, v := range e.Attributes {
		child, err := v.Marshal()
		if err != nil {
			return nil, err
		}

		attributes.AppendChild(child)
	}
	packet.AppendChild(attributes)

	return packet, nil
}

func (e *SearchResultEntry) Unmarshal(packet *ber.Packet) (err error) {
	packet = packet.Children[1] // Skip MessageID

	e.DN = packet.Children[0].Value.(string)
	e.Attributes = make([]*PartialAttributeList, len(packet.Children[1].Children))
	for i, attribute := range packet.Children[1].Children {
		if err = e.Attributes[i].Unmarshal(attribute); err != nil {
			return err
		}
	}

	return
}

///////////////////////////////////////////////////////

var _ IBerMessage = (*PartialAttributeList)(nil)

type PartialAttributeList struct {
	Name   string
	Values []string
}

func (e *PartialAttributeList) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "partialAttributeList")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.Name, "type"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, v := range e.Values {
		attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
	}
	packet.AppendChild(attributes)

	return packet, nil
}

func (e *PartialAttributeList) Unmarshal(packet *ber.Packet) error {
	e.Name = packet.Children[0].Value.(string) // Name
	// Pre-allocate, since we can determine the length at this point
	e.Values = make([]string, len(packet.Children[1].Children))

	for i, v := range packet.Children[1].Children { // Values
		e.Values[i] = v.Value.(string)
	}

	return nil
}

///////////////////////////////////////////////////////

var _ IBerMessage = (*SearchResultDone)(nil)

type SearchResultDone struct {
	LDAPResult
}

func (s *SearchResultDone) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "SearchResultDone")
	s.AddPackets(packet)
	return packet, nil
}

func (s *SearchResultDone) Unmarshal(packet *ber.Packet) error {
	return nil
}
