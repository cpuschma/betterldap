package main

import (
	"betterldap"
	"encoding/base32"
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
	conn, err := betterldap.Dial("tcp", "127.0.0.1:389", betterldap.ConnectionOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	fmt.Printf("Bind: ")
	bindResult, err := conn.Bind(betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "cn=admin,dc=my-company,dc=com",
		Password: "admin123!",
	})
	fmt.Println(bindResult, err)

	b := randomBytes(16)
	result, err := conn.Modify(betterldap.ModifyRequest{
		Object: "uid=Otto.Baumann,ou=Users,ou=LEJ-02,ou=DE,ou=Locations,dc=my-company,dc=com",
		Changes: []betterldap.ModifyChanges{
			{
				Operation: betterldap.ModifyOperationReplace,
				Modification: betterldap.PartialAttribute{
					Name:   "displayName",
					Values: []string{base32.StdEncoding.EncodeToString(b)},
				},
			},
		},
	})

	fmt.Println(result, err)
}
