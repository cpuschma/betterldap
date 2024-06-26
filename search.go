package betterldap

import (
	"errors"
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
//		sizeLimit       INTEGER ,
//		timeLimit       INTEGER,
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
	Controls     []Control
}

func (s *SearchRequest) Marshal() (*ber.Packet, *ber.Packet) {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.BaseDN, "Base DN"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, s.Scope, "Scope"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, s.DerefAliases, "Deref Aliases"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.SizeLimit, "Size Limit"))
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.TimeLimit, "Time Limit"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "Types Only"))

	filterPacket, err := CompileFilter(s.Filter)
	if err != nil {
		return nil, nil
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

func (s *SearchRequest) Unmarshal(packet *ber.Packet, _ *ber.Packet) (err error) {
	s.BaseDN = packet.Children[0].Value.(string)
	s.Scope = packet.Children[1].Value.(int64)
	s.DerefAliases = packet.Children[2].Value.(int64)
	s.SizeLimit = packet.Children[3].Value.(int64)
	s.TimeLimit = packet.Children[4].Value.(int64)
	s.TypesOnly = packet.Children[5].Value.(bool)

	filter, err := DecompileFilter(packet.Children[6])
	if err != nil {
		return err
	}
	s.Filter = filter

	s.Attributes = make([]string, len(packet.Children[7].Children))
	for i, attribute := range packet.Children[7].Children {
		s.Attributes[i] = attribute.Value.(string)
	}

	return
}

func (c *Conn) Search(req *SearchRequest) (*SearchResult, error) {
	if req.Filter == "" {
		req.Filter = "(objectClass=*)"
	}

	packet, _ := req.Marshal()
	envelope, handler := c.NewMessage(packet, encodeControls(req.Controls))
	c.AddHandler(envelope.MessageID, handler)
	defer c.RemoveHandler(envelope.MessageID)

	err := c.SendMessage(envelope.Marshal())
	if err != nil {
		return nil, err
	}

	searchResult := &SearchResult{}
scanLoop:
	for {
		envelope, ok := handler.Receive()
		if !ok {
			return nil, errors.New("handler closed")
		}

		if envelope.Controls != nil {
			controls, err := DecodeControls(envelope.Controls)
			if err != nil {
				return nil, err
			}

			searchResult.Controls = controls
		}

		switch envelope.Packet.Tag {
		case ApplicationSearchResultEntry:
			entry := &SearchResultEntry{}
			if err = entry.Unmarshal(envelope.Packet, envelope.Controls); err != nil {
				return nil, err
			}

			searchResult.Entries = append(searchResult.Entries, entry)
		case ApplicationSearchResultReference:
			searchResult.Referrals = append(searchResult.Referrals, envelope.Packet.Children[0].Data.String())
		case ApplicationSearchResultDone:
			if err = searchResult.LDAPResult.Unmarshal(envelope.Packet, envelope.Controls); err != nil {
				return nil, err
			}

			searchResult.Controls, err = DecodeControls(envelope.Controls)
			break scanLoop
		default:
			return nil, fmt.Errorf("invalid tag for search response: %d", envelope.Packet.Tag)
		}
	}

	return searchResult, err
}

func (c *Conn) SearchWithPaging(searchRequest *SearchRequest, size int32) (*SearchResult, error) {
	var pagingControl *ControlPagedResults

	if p := FindControl(searchRequest.Controls, ControlTypePaging); p == nil {
		pagingControl = &ControlPagedResults{
			Size: size,
		}
		searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	} else {
		pagingControl = p.(*ControlPagedResults)
	}

	searchResult := &SearchResult{}
	for {
		result, err := c.Search(searchRequest)
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, errors.New("packets not received")
		}

		searchResult.Entries = append(searchResult.Entries, result.Entries...)
		searchResult.Controls = append(searchResult.Controls, result.Controls...)
		searchResult.Referrals = append(searchResult.Referrals, result.Referrals...)

		// Atleast in Active Directory, the cookie will be sent
		// on the searchResDone packet. Since Search returns when
		// this packet has been received, we can safely wait and append
		// all results in the meantime
		pagingResult := FindControl(result.Controls, ControlTypePaging)
		if pagingResult == nil {
			pagingControl = nil
			break
		}

		cookie := pagingResult.(*ControlPagedResults).Cookie
		if len(cookie) == 0 {
			break
		}

		pagingControl.Cookie = cookie
	}

	// TODO: wtf is this
	// https://github.com/go-ldap/ldap/blob/master/v3/search.go#L349
	//if pagingControl != nil {
	//	pagingControl.Size = 0
	//	c.Search(searchRequest)
	//}

	return searchResult, nil
}
