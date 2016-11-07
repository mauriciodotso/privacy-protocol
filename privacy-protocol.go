package main

import (
	"flag"
	"fmt"

	"github.com/mauriciodotso/privacy-protocol/idp"
)

func clientNativeMessaging(port uint) {
	fmt.Printf("Starting in client mode on port %d.\n", port)
	fmt.Println("Press Ctrl-C to stop.")
	// TODO
}

func serviceProvider(port uint, name string) {
	fmt.Printf("Starting in service provider mode on port %d.\n", port)
	fmt.Println("Press Ctrl-C to stop.")
	// TODO
}

func identityProvider(port uint, name string) {
	fmt.Printf("Starting in identity provider mode on port %d.\n", port)
	fmt.Println("Press Ctrl-C to stop.")

	idp.RunIdP(port, name)
}

func main() {
	modePtr := flag.String("mode", "client", "The mode that this program is going to operate. The modes are 'client', 'SP' and 'IdP'")
	portPtr := flag.Uint("port", 5005, "The port that this program should use")
	namePtr := flag.String("name", "Service Provider 1", "The name of the service this program is running")
	flag.Parse()

	if *modePtr == "client" {
		clientNativeMessaging(*portPtr)
	}
	if *modePtr == "SP" {
		serviceProvider(*portPtr, *namePtr)
	}
	if *modePtr == "IdP" {
		identityProvider(*portPtr, *namePtr)
	}
}
