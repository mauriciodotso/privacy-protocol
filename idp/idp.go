package idp

import (
	"fmt"
	"net"
)

type identityProvider struct {
	port uint
	name string
}

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

func (idp *identityProvider) handleConnection(c net.Conn) {
	// TODO
}

func RunIdP(port uint, name string) {
	var my_idp identityProvider
	my_idp.name = name
	my_idp.port = port
	my_idp.Run()
}
