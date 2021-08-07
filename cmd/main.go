package main

import (
	"betterldap"
	"betterldap/internal/debug"
	"fmt"
)

func main() {
	//data, _ := ioutil.ReadFile("./testdata/searchRequest_ou.bin")
	//packet := ber.DecodePacket(data)
	//
	//envelope := &betterldap.Envelope{}
	//envelope.Unmarshal(packet)
	//
	//searchRequest := &betterldap.SearchRequest{}
	//fmt.Println(searchRequest.Unmarshal(envelope.Packet, envelope.Controls))
	//debug.Logf("%#v\n", packet)
	//return

	conn, err := betterldap.Dial("tcp", "127.0.0.1:389", betterldap.ConnectionOptions{})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	go conn.ReadIncomingMessages()

	fmt.Printf("Bind: ")
	fmt.Println(conn.Bind(&betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "cn=admin,dc=my-company,dc=com",
		Password: "admin123!",
	}))

	searchResult, err := conn.Search(&betterldap.SearchRequest{
		BaseDN:       "ou=Users,ou=LEJ-02,ou=DE,ou=Locations,dc=my-company,dc=com",
		Scope:        betterldap.ScopeWholeSubtree,
		DerefAliases: betterldap.NeverDerefAliases,
		Filter:       "(objectclass=inetOrgPerson)",
		Attributes:   []string{"cn"},
	})
	if err != nil {
		panic(err)
	}
	debug.Logf("%#v\n", searchResult)
}
