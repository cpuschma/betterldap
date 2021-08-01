package betterldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var _ IBerMessage = (*SearchRequest)(nil)

// https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
//	SearchRequest ::= [APPLICATION 3] SEQUENCE {
//		baseObject      LDAPDN,
//		scope           ENUMERATED {
//		baseObject              (0),
//		singleLevel             (1),
//		wholeSubtree            (2),
//		...  },
//		derefAliases    ENUMERATED {
//		neverDerefAliases       (0),
//		derefInSearching        (1),
//		derefFindingBaseObj     (2),
//		derefAlways             (3) },
//		sizeLimit       INTEGER (0 ..  maxInt),
//		timeLimit       INTEGER (0 ..  maxInt),
//		typesOnly       BOOLEAN,
//		filter          Filter,
//		attributes      AttributeSelection }

type SearchRequest struct {
	BaseDN       string
	Scope        int64
	DerefAliases int64
	SizeLimit    int64
	TimeLimit    int64
	TypesOnly    bool
	Filter       string
	Attributes   []string
}

func (s *SearchRequest) Marshal() (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.BaseDN, "Base DN"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, s.Scope, "Scope"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, s.DerefAliases, "Deref Aliases"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.SizeLimit, "Size Limit"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.TimeLimit, "Time Limit"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "Types Only"))

	filterPacket, err := CompileFilter(s.Filter)
	if err != nil {
		return nil, err
	}
	packet.AppendChild(filterPacket)

	attributes := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence, nil, "Attributes")
	for _, v := range s.Attributes {
		attributes.AppendChild(
			ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				v,
				"Attribute",
			),
		)
	}

	packet.AppendChild(attributes)
	return packet, nil
}

func (s *SearchRequest) Unmarshal(packet *ber.Packet) (err error) {
	searchPacket := packet.Children[1] // Skip MessageID

	s.BaseDN = searchPacket.Children[0].Value.(string)
	s.Scope = searchPacket.Children[1].Value.(int64)
	s.DerefAliases = searchPacket.Children[2].Value.(int64)
	s.SizeLimit = searchPacket.Children[3].Value.(int64)
	s.TimeLimit = searchPacket.Children[4].Value.(int64)
	s.TypesOnly = searchPacket.Children[5].Value.(bool)

	filter, err := DecompileFilter(searchPacket.Children[6])
	if err != nil {
		return err
	}
	s.Filter = filter

	s.Attributes = make([]string, len(searchPacket.Children[7].Children))
	for i, attribute := range searchPacket.Children[7].Children {
		s.Attributes[i] = attribute.Value.(string)
	}

	return
}

func (c *Client) Search(req *SearchRequest) (*SearchResult, error) {
	packet, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal of search request failed: %w", err)
	}

	err = c.SendMessage(packet)
	searchResult := &SearchResult{}
	for {
		responsePacket, err := c.ReadPacket()
		if err != nil {
			return nil, err
		}
		_ = responsePacket
		// TODO: Create SearchResult and scan entries

		break
	}

	return searchResult, nil
}
