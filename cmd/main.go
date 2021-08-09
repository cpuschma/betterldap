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

	conn, err := betterldap.Dial("tcp", "192.168.243.131:389", betterldap.ConnectionOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	fmt.Printf("Bind: ")
	fmt.Println(conn.Bind(&betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "administrator@collaboration.local",
		Password: "admin123!",
	}))

	searchResult, err := conn.Search(&betterldap.SearchRequest{
		BaseDN:       "OU=Users,OU=LEJ-02,OU=DE,OU=Locations,DC=collaboration,DC=local",
		Scope:        betterldap.ScopeWholeSubtree,
		DerefAliases: betterldap.NeverDerefAliases,
		Filter:       "(mail=*)",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	if searchResult == nil {
		fmt.Println("searchResult is nil, but got no error?")
		return
	}

	for _, v := range searchResult.Entries {
		fmt.Printf("DN: %s\n", v.DN)
		for _, attribute := range v.Attributes {
			fmt.Printf("  %s: %s\n", attribute.Name, attribute)
		}
		fmt.Println()
	}
	debug.Logf("%#v\n", searchResult)
	fmt.Println("Unbind:", conn.Unbind())

}
