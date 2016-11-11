package idp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"net"
)

type userInternalData struct {
	userKey    publicKey
	userInfo   userInfo
	sessionKey simetricKey
}

/*
The type for an Identity Provider in the protocol
*/
type identityProvider struct {
	port      uint
	name      string
	publicKey publicKey

	users      []userInternalData
	privateKey privateKey
}

//Follows the structures for Identity Creation within the IdP
type simetricKey struct {
	keyData []byte
}

type privateKey struct {
	keyData []byte
}

type publicKey struct {
	keyData []byte
}

type signature struct {
	content   []byte
	algorithm string
	signatute []byte
}

type ackNack struct {
	ackNack bool
}

const SessionInfo = 0
const Ack = 0

type messageFromIdP struct {
	messageId uint
	content   []byte
}

const UserIdentity = 0
const UserInfo = 1
const UserAuthentication = 2

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
		log.Fatal(err)
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
		log.Print(err)
		c.Close()
		return
	}

	var toIdp messageToIdP
	asn1.Unmarshal(message, &toIdp)
	if toIdp.messageId == UserIdentity {
		var uIdentity publicKey
		asn1.Unmarshal(toIdp.content, &uIdentity)

		uid := idp.findUserInternalData(uIdentity)
		if uid == nil {
			new_uid := userInternalData{userKey: uIdentity}
			idp.users = append(idp.users, new_uid)
			uid = &new_uid
		}

		uid.sessionKey = simetricKey{keyData: make([]byte, 256)}
		_, err := rand.Read(uid.sessionKey.keyData)
		if err != nil {
			log.Print(err)
			c.Close()
			return
		}
		idp.sendSession(uid, c)
	}

	if toIdp.messageId == UserInfo {
		var uInfo userInfo
		asn1.Unmarshal(toIdp.content, &uInfo)
	}
}

func (idp *identityProvider) sendSession(uid *userInternalData, c net.Conn) {
	sInfo := sessionInfo{sessionKey: uid.sessionKey, idp: idp.publicKey}
	signedSessionInfo := sign(sInfo, idp.privateKey)

	// The messageId is unprotected!!!
	content, err := asn1.Marshal(signedSessionInfo)
	if err != nil {
		log.Print(err)
		c.Close()
	} else {
		mFromIdP := messageFromIdP{messageId: SessionInfo, content: content}
		idp.sendMessageAssimetric(mFromIdP, uid.userKey, c)
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
	block, err := aes.NewCipher(sessionKey.keyData)
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
	for _, uData := range idp.users {
		userKeyLen := len(userKey.keyData)
		uDataLen := len(uData.userKey.keyData)

		if userKeyLen != uDataLen {
			continue
		}

		var equality bool
		for i := range userKey.keyData {
			// May be subject to timing attacks
			equality = equality && (userKey.keyData[i] == uData.userKey.keyData[i])
		}
		if equality {
			result = &uData
		}
	}

	return result
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
