package main

import (
	"betterldap"
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestMain(t *testing.M) {
	//defer profile.Start(profile.MemProfile).Stop()
	t.Run()
}

func BenchmarkOldSearch(b *testing.B) {
	b.StopTimer()
	conn, _ := ldap.Dial("tcp", "192.168.243.131:389")
	conn.Bind("administrator@collaboration.local", "admin123!")
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := conn.Search(&ldap.SearchRequest{
			BaseDN:       "OU=Users,OU=LEJ-02,OU=DE,OU=Locations,DC=collaboration,DC=local",
			Scope:        betterldap.ScopeWholeSubtree,
			DerefAliases: betterldap.NeverDerefAliases,
			Filter:       "(mail=*@collaboration.local)",
		})
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkNewSearch(b *testing.B) {
	b.StopTimer()
	conn, err := betterldap.Dial("tcp", "192.168.243.131:389", betterldap.ConnectionOptions{})
	if err != nil {
		panic(err)
	}
	conn.Bind(&betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "administrator@collaboration.local",
		Password: "admin123!",
	})
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err = conn.Search(&betterldap.SearchRequest{
			BaseDN:       "OU=Users,OU=LEJ-02,OU=DE,OU=Locations,DC=collaboration,DC=local",
			Scope:        betterldap.ScopeWholeSubtree,
			DerefAliases: betterldap.NeverDerefAliases,
			Filter:       "(mail=*@collaboration.local)",
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
