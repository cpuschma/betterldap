package main

import (
	"betterldap"
	"betterldap/internal/debug"
	ber "github.com/go-asn1-ber/asn1-ber"
	"io/ioutil"
	"net"
	"time"
)

func main() {
	data, _ := ioutil.ReadFile("./cmd/search_request_result.bin")
	packet := ber.DecodePacket(data)

	var s = new(betterldap.SearchResult)
	debug.Log(s.Unmarshal(packet))
	return

	conn, err := betterldap.Dial("tcp", "127.0.0.1:389", betterldap.ConnectionOptions{
		Dialer: net.Dialer{
			Timeout: 5 * time.Second,
		},
	})
	if err != nil {
		debug.Log(err)
		return
	}

	result, err := conn.Bind(&betterldap.SimpleBindRequest{
		DN:       "cn=admin,dc=my-company,dc=com",
		Password: "robin123!",
	})
	if err != nil {
		panic(err)
	}
	debug.Logf("%#v\n", result)

	searchRequest := &betterldap.SearchRequest{
		BaseDN:       "ou=Users,dc=my-company,dc=com",
		Scope:        betterldap.ScopeWholeSubtree,
		DerefAliases: betterldap.NeverDerefAliases,
		TypesOnly:    false,
		Attributes:   []string{"cn"},
		Filter:       "(objectclass=*)",
	}
	conn.Search(searchRequest)
}
