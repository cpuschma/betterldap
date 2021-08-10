package betterldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SearchResult)(nil)

type SearchResult struct {
	Entries   []*SearchResultEntry
	Referrals []string
	Controls  []Control

	LDAPResult
}

func (s *SearchResult) Marshal() (*ber.Packet, *ber.Packet) {
	return nil, nil
}

func (s *SearchResult) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
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
	Attributes []PartialAttribute
}

func (e *SearchResultEntry) Marshal() (*ber.Packet, *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagOctetString, nil, "searchResultEntry")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, v := range e.Attributes {
		child, _ := v.Marshal()
		attributes.AppendChild(child)
	}
	packet.AppendChild(attributes)

	return packet, nil
}

func (e *SearchResultEntry) Unmarshal(packet *ber.Packet, _ *ber.Packet) (err error) {
	e.DN = packet.Children[0].Value.(string)
	e.Attributes = make([]PartialAttribute, len(packet.Children[1].Children))
	for i, attribute := range packet.Children[1].Children {
		e.Attributes[i] = PartialAttribute{}
		if err = e.Attributes[i].Unmarshal(attribute, nil); err != nil {
			return err
		}
	}

	return
}

///////////////////////////////////////////////////////

var _ IBerMessage = (*PartialAttribute)(nil)

type PartialAttribute struct {
	Name   string
	Values []string
}

func (p *PartialAttribute) Marshal() (*ber.Packet, *ber.Packet) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, p.Name, ""))

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
	for _, v := range p.Values {
		attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
	}
	packet.AppendChild(attributes)

	return packet, nil
}

func (p *PartialAttribute) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
	p.Name = packet.Children[0].Data.String() // Name
	// Pre-allocate, since we can determine the length at this point
	p.Values = make([]string, len(packet.Children[1].Children))

	for i, v := range packet.Children[1].Children { // Values
		p.Values[i] = v.Value.(string)
	}

	return nil
}

func (p *PartialAttribute) String() string {
	if len(p.Values) > 0 {
		return p.Values[0]
	}

	return ""
}

///////////////////////////////////////////////////////

var _ IBerMessage = (*SearchResultDone)(nil)

type SearchResultDone struct {
	LDAPResult
}

func (s *SearchResultDone) Marshal() (*ber.Packet, *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search Result Done")
	s.AddPackets(packet)
	return packet, nil
}

func (s *SearchResultDone) Unmarshal(packet *ber.Packet, _ *ber.Packet) error {
	return nil
}
