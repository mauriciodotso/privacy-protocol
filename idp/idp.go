package idp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

type userInternalData struct {
	UserKey    publicKey
	UserInfo   userInfo
	SessionKey simetricKey
}

/*
The type for an Identity Provider in the protocol
*/
type identityProvider struct {
	Port      uint
	Name      string
	PublicKey publicKey

	Users      []userInternalData
	PrivateKey privateKey
	Control    chan bool
	WaitGroup  *sync.WaitGroup
}

//Follows the structures for Identity Creation within the IdP
type simetricKey struct {
	KeyData []byte
}

type privateKey struct {
	KeyData []byte
}

type publicKey struct {
	KeyData []byte
}

type signature struct {
	Content   []byte
	Algorithm string
	Signatute []byte
}

type ackNack struct {
	AckNack bool
}

const SessionInfo = 0
const Ack = 0

type messageFromIdP struct {
	MessageId int
	Content   []byte
}

const UserIdentity = 0
const UserInfo = 1
const UserAuthentication = 2

type messageToIdP struct {
	MessageId int
	Content   []byte
}

type personalInfo struct {
	Data []byte
}

type idpMessage struct {
	MessageId int
	Content   []byte
}

type sessionInfo struct {
	SessionKey simetricKey
	Idp        publicKey
}

// Follows the structures for user authentication within the IdP
type userInfo struct {
	PersonalInfo    []byte
	ServiceProvider publicKey
}

// Follows a simple personalInfo for this IdP
type personalInfoData struct {
	Name     string
	Email    string
	Age      byte
	Address  string
	Password string
}

type personalInfoDataAuthentication struct {
	Email    string
	Password string
}

/*
Starts the Identity Provider
*/
func (idp *identityProvider) Run() {
	log.Println(fmt.Sprintf("Running the IdP \"%s\" in the port %d.", idp.Name, idp.Port))
	defer idp.WaitGroup.Done()
	laddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", idp.Port))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp", laddr)
	defer ln.Close()
	log.Println("Listening on:", laddr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		case <-idp.Control:
			log.Println("Stopping server on ", ln.Addr())
			return
		default:
		}
		// accept a connection
		ln.SetDeadline(time.Now().Add(1000 * time.Millisecond))
		log.Println("Awaiting connection")
		c, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		// handle the connection
		go idp.handleConnection(c)
	}
}

func (idp *identityProvider) Stop() {
	log.Println("Stopping the server.")
	idp.Control <- true
	close(idp.Control)
	idp.WaitGroup.Wait()
}

/*
Deals with the connection to the Identity Provider.
This is the entry point for the protocol proposed.
*/
func (idp *identityProvider) handleConnection(c net.Conn) {
	log.Println("Handling connection")
	message, err := ioutil.ReadAll(c)
	if err != nil {
		log.Print(err)
		return
	}
	log.Println("Message received:", message)

	var toIdp messageToIdP
	asn1.Unmarshal(message, &toIdp)
	log.Println("Message parsed:", toIdp)
	if toIdp.MessageId == UserIdentity {
		log.Println("Message is UserIdentity")
		var uIdentity publicKey
		asn1.Unmarshal(toIdp.Content, &uIdentity)
		log.Println("User identity parsed:", uIdentity)
		uid := idp.findUserInternalData(uIdentity)
		if uid == nil {
			log.Println("New user identity, allocating data")
			new_uid := userInternalData{UserKey: uIdentity}
			idp.Users = append(idp.Users, new_uid)
			uid = &new_uid
		}

		uid.SessionKey = simetricKey{KeyData: make([]byte, 256)}
		_, err := rand.Read(uid.SessionKey.KeyData)
		log.Println("Generated Session Key")
		if err != nil {
			log.Print(err)
			c.Close()
			return
		}
		idp.sendSession(uid, c)
	}

	if toIdp.MessageId == UserInfo {
		log.Println("Message is UserInfo")
		var uInfo userInfo
		asn1.Unmarshal(toIdp.Content, &uInfo)
	}
	c.Close()
}

func (idp *identityProvider) sendSession(uid *userInternalData, c net.Conn) {
	sInfo := sessionInfo{SessionKey: uid.SessionKey, Idp: idp.PublicKey}
	signedSessionInfo := sign(sInfo, idp.PrivateKey)

	// The messageId is unprotected!!!
	content, err := asn1.Marshal(signedSessionInfo)
	log.Println("Session key encoded")
	if err != nil {
		log.Print(err)
		return
	} else {
		mFromIdP := messageFromIdP{MessageId: SessionInfo, Content: content}
		idp.sendMessageAssimetric(mFromIdP, uid.UserKey, c)
	}
}

func (idp *identityProvider) sendMessageAssimetric(message interface{}, pKey publicKey, c net.Conn) {
	messageBytes, err := asn1.Marshal(message)
	if err != nil {
		log.Print(err)
		c.Close()
		return
	}

	pubKey := parsePublicKey(pKey)
	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, messageBytes, nil)
	if err != nil {
		log.Print(err)
		c.Close()
		return
	}

	c.Write(encryptedMessage)
}

func (idp *identityProvider) sendMessageSimetric(message interface{}, sessionKey simetricKey, c net.Conn) {
	messageBytes, err := asn1.Marshal(message)
	if err != nil {
		log.Print(err)
		return
	}
	block, err := aes.NewCipher(sessionKey.KeyData)
	if err != nil {
		log.Print(err)
		c.Close()
		return
	}

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	// FIXME: Missing authentication of the message? (Padding Oracle)
	mode.CryptBlocks(messageBytes, messageBytes)

	c.Write(messageBytes)
}

func parsePublicKey(pKey publicKey) *rsa.PublicKey {
	// TODO
	return nil
}

func sign(message interface{}, pKey privateKey) []byte {
	// TODO
	return make([]byte, 0)
}

func (idp *identityProvider) findUserInternalData(userKey publicKey) *userInternalData {
	var result *userInternalData
	for _, uData := range idp.Users {
		userKeyLen := len(userKey.KeyData)
		uDataLen := len(uData.UserKey.KeyData)

		if userKeyLen != uDataLen {
			continue
		}

		var equality bool
		for i := range userKey.KeyData {
			// May be subject to timing attacks
			equality = equality && (userKey.KeyData[i] == uData.UserKey.KeyData[i])
		}
		if equality {
			result = &uData
		}
	}

	return result
}

func RunIdP(port uint, name string) identityProvider {
	var my_idp identityProvider
	my_idp.Name = name
	my_idp.Port = port
	my_idp.Control = make(chan bool)
	my_idp.WaitGroup = &sync.WaitGroup{}
	my_idp.WaitGroup.Add(1)
	go my_idp.Run()
	return my_idp
}
