package main

import (
	"betterldap"
	"fmt"
)

func main() {
	//data, _ := ioutil.ReadFile("./testdata/paging.bin")
	//packet := ber.DecodePacket(data)
	//
	//envelope := &betterldap.Envelope{}
	//envelope.Unmarshal(packet)
	//
	//c, err := betterldap.DecodeControl(envelope.Controls.Children[0])
	//if err != nil {
	//	panic(err)
	//}
	//
	//debug.Logf("%#v\n", c)
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

	searchResult, err := conn.SearchWithPaging(&betterldap.SearchRequest{
		BaseDN:       "DC=collaboration,DC=local",
		Scope:        betterldap.ScopeWholeSubtree,
		DerefAliases: betterldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
	}, 3)
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
			fmt.Printf("  %s: %s\n", attribute.Name, attribute.String())
		}
		fmt.Println()
	}

	fmt.Println("Search result entries:", len(searchResult.Entries))
	fmt.Println("Unbind:", conn.Unbind())
}
