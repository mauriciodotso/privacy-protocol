package idp

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"net"
)

/*
The type for an Identity Provider in the protocol
*/
type identityProvider struct {
	port uint
	name string
}

//Follows the structures for Identity Creation within the IdP
type simetricKey struct {
}

type publicKey struct {
}

type signature struct {
	content   []byte
	algorithm string
	signatute []byte
}

type ackNack struct {
	ackNack byte
}

type messageToIdP struct {
	messageId uint
	content   []byte
}

type personalInfo struct {
	data []byte
}

type idpMessage struct {
	messageId uint
	content   []byte
}

type sessionInfo struct {
	sessionKey simetricKey
	idp        publicKey
}

// Follows the structures for user authentication within the IdP
type userInfo struct {
	personalInfo    []byte
	serviceProvider publicKey
}

// Follows a simple personalInfo for this IdP
type personalInfoData struct {
	name     string
	email    string
	age      byte
	address  string
	password string
}

type personalInfoDataAuthentication struct {
	email    string
	password string
}

/*
Starts the Identity Provider
*/
func (idp *identityProvider) Run() {
	fmt.Printf("Running the IdP \"%s\" in the port %d.\n", idp.name, idp.port)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", idp.port))
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		// accept a connection
		c, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		// handle the connection
		go idp.handleConnection(c)
	}
}

/*
Deals with the connection to the Identity Provider.
This is the entry point for the protocol proposed.
*/
func (idp *identityProvider) handleConnection(c net.Conn) {
	message, err := readFully(c)
	if err != nil {
		log.Fatal(err)
	}

	var toIdp messageToIdP
	asn1.Unmarshal(message, &toIdp)
	if toIdp.messageId == 0 {

	}
	if toIdp.messageId == 1 {

	}
}

func readFully(conn net.Conn) ([]byte, error) {
	defer conn.Close()

	result := bytes.NewBuffer(nil)
	var buf [512]byte
	for {
		n, err := conn.Read(buf[0:])
		result.Write(buf[0:n])
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return result.Bytes(), nil
}

func RunIdP(port uint, name string) {
	var my_idp identityProvider
	my_idp.name = name
	my_idp.port = port
	my_idp.Run()
}
