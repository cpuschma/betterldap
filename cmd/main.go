package main

import (
	"betterldap"
	"fmt"
	"time"
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

	conn, err := betterldap.Dial("tcp", "10.203.156.32:389", betterldap.ConnectionOptions{})
	if err != nil {
		panic(err)
	}

	go conn.ReadIncomingMessages()

	fmt.Printf("Bind: ")
	fmt.Println(conn.Bind(&betterldap.SimpleBindRequest{
		Version:  3,
		DN:       "christopher.puschmann@login.ds.signintra.com",
		Password: "5R@9mC%SaRdHb2",
	}))

	fmt.Println("sleep 2sec")
	time.Sleep(2 * time.Second)
	fmt.Println(conn.Close())
	time.Sleep(2 * time.Second)
	fmt.Println(conn.Close())

}
