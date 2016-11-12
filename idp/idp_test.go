package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"io/ioutil"
	//	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"
)

func TestRunIdP(t *testing.T) {
	idp := RunIdP(50005, "test IdP")
	time.Sleep(100 * time.Millisecond)
	idp.Stop()
}

func TestFirstIteration(t *testing.T) {
	idp := RunIdP(50005, "test IdP")
	defer idp.Stop()
	time.Sleep(100 * time.Millisecond)
	raddr, err := net.ResolveTCPAddr("tcp", "localhost:50005")
	conn, err := net.DialTCP("tcp", nil, raddr)
	log.Println("Test:", "Dialed to server")
	if err != nil {
		log.Println("Test:", err)
		return
	}
	defer conn.Close()

	keyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	userPublicKey, _ := asn1.Marshal(keyPair.Public())
	userPKey, _ := asn1.Marshal(publicKey{KeyData: userPublicKey})
	toIdpMessage := messageToIdP{MessageId: UserIdentity, Content: userPKey}
	messageBytes, _ := asn1.Marshal(toIdpMessage)
	log.Println("Test:", "Message marshalled")
	log.Println("Test:", messageBytes)
	_, err = conn.Write(messageBytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Test:", "Message sent, wating response")

	response, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Println("Test:", err)
		return
	}
	log.Println("Test:", "Response:", response)

}
