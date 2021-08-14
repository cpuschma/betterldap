package main

import (
	"betterldap"
	"fmt"
	"math/rand"
)

func randomBytes(len int) []byte {
	b := make([]byte, len)
	for i := 0; i < len; i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func main() {
	conn, err := betterldap.Dial("tcp", "192.168.243.131:389", betterldap.ConnectionOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	fmt.Printf("Bind: ")
	bindResult, err := conn.Bind(betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "administrator@collaboration.local",
		Password: "admin123!",
	})
	fmt.Println(bindResult, err)

	searchResult, err := conn.Search(&betterldap.SearchRequest{
		BaseDN:       "ou=Users,ou=LEJ-02,ou=DE,ou=Locations,dc=collaboration,dc=local",
		Scope:        betterldap.ScopeWholeSubtree,
		DerefAliases: betterldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
		Controls: []betterldap.Control{
			betterldap.ControlAccountUsable{},
		},
	})

	fmt.Println(searchResult, err)
	println()
}
