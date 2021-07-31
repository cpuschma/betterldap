package main

import (
	"betterldap"
	"fmt"
	"net"
	"time"
)

func main() {
	//data, _ := ioutil.ReadFile("./cmd/search_result_entry.bin")
	//packet := ber.DecodePacket(data)
	//println(packet)
	//return

	conn, err := betterldap.Dial("tcp", "127.0.0.1:389", betterldap.ConnectionOptions{
		Dialer: net.Dialer{
			Timeout: 5 * time.Second,
		},
	})
	if err != nil {
		panic(err)
	}

	result, err := conn.Bind(&betterldap.SimpleBindRequest{
		DN:       "cn=admin,dc=my-company,dc=com",
		Password: "robin123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", result)

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
