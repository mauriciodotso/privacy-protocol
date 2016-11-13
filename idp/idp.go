package idp

import (
	"crypto"
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
	"time"
)

type userInternalData struct {
	UserKey    publicKey
	UserInfo   userInfo
	SessionKey simetricKey
}

type IdentityProviderService interface {
	UserIdentity(userPublicKey publicKey) (sessionInfo, error)
	UserInformation(userPublicKey publicKey, userInformation userInfo) (ackNack, error)
}

type Transporter interface {
	Receive(message []byte) (interface{}, error)
	Transmit(message []byte) error
}

type Server interface {
	Listen() error
	Stop() error
}

/*
The type for an Identity Provider in the protocol
*/
type identityProvider struct {
	Port      uint
	Name      string
	PublicKey publicKey

	Users      []userInternalData
	PrivateKey *rsa.PrivateKey
	Control    chan bool
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
func (idp *identityProvider) Listen() error {
	log.Println(fmt.Sprintf("Starting the Identity Provider \"%s\" at the port %d.", idp.Name, idp.Port))
	laddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", idp.Port))
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	defer ln.Close()
	log.Println("Listening on:", laddr)
	if err != nil {
		return err
	}
	for {
		select {
		case <-idp.Control:
			log.Println("Stopping server on ", ln.Addr())
			return nil
		default:
		}
		// accept a connection
		ln.SetDeadline(time.Now().Add(100 * time.Millisecond))
		//log.Println("Awaiting connection")
		c, err := ln.Accept()
		if err != nil {
			//log.Println(err)
			continue
		}
		// handle the connection
		go idp.handleConnection(c)
	}
}

func (idp *identityProvider) Stop() {
	log.Println("Stopping the server.")
	idp.Control <- true
}

/*
Deals with the connection to the Identity Provider.
This is the entry point for the protocol proposed.
*/
func (idp *identityProvider) handleConnection(c net.Conn) {
	log.Println("Handling connection")
	defer c.Close()
	var uIdentity publicKey
	var toIdp messageToIdP
	var sInfo sessionInfo
	var err error
	for {
		log.Print("Reading message")
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		message, _ := ioutil.ReadAll(c)
		log.Println("Message received:", message)
		asn1.Unmarshal(message, &toIdp)
		log.Println("Message parsed:", toIdp)
		if toIdp.MessageId == UserIdentity {
			log.Println("Message is UserIdentity")
			asn1.Unmarshal(toIdp.Content, &uIdentity)
			sInfo, err = idp.UserIdentity(uIdentity)
			if err != nil {
				log.Print(err)
				return
			}
			signedSessionInfo, err := Sign(sInfo, idp.PrivateKey)
			if err != nil {
				log.Println(err)
				return
			}
			m := messageFromIdP{MessageId: SessionInfo, Content: signedSessionInfo}
			idp.sendMessageAssimetric(m, uIdentity, c)
		} else if toIdp.MessageId == UserInfo {
			log.Println("Message is UserInfo")
			if uIdentity.KeyData == nil {
				log.Println("Wrong order of messages. Ending Connection.")
				return
			}
			var uInfo userInfo
			asn1.Unmarshal(toIdp.Content, &uInfo)
			ack, err := idp.UserInformation(uIdentity, uInfo)
			if err != nil {
				log.Println(err)
				return
			}
			encodedAck, err := asn1.Marshal(ack)
			if err != nil {
				log.Println(err)
				return
			}
			m := messageFromIdP{MessageId: Ack, Content: encodedAck}
			idp.sendMessageSimetric(m, sInfo.SessionKey, c)
			log.Println("Protocol executed sucessully. Ending connection.")
			return
		} else {
			log.Println("Unknow message. Ending connection.")
			return
		}
	}
}

func (idp *identityProvider) UserIdentity(userPublicKey publicKey) (sessionInfo, error) {
	log.Println("User identity parsed:", userPublicKey)
	uid := idp.findUserInternalData(userPublicKey)
	if uid == nil {
		log.Println("New user identity, allocating data")
		new_uid := userInternalData{UserKey: userPublicKey}
		idp.Users = append(idp.Users, new_uid)
		uid = &new_uid
	}

	uid.SessionKey = simetricKey{KeyData: make([]byte, 256)}
	_, err := rand.Read(uid.SessionKey.KeyData)
	log.Println("Generated Session Key")
	if err != nil {
		return sessionInfo{}, err
	}

	sInfo := sessionInfo{SessionKey: uid.SessionKey, Idp: idp.PublicKey}
	return sInfo, nil
}

func (idp *identityProvider) UserInformation(userPublicKey publicKey, userInfo userInfo) (ackNack, error) {
	// TODO
	return ackNack{AckNack: true}, nil
}

func (idp *identityProvider) sendMessageAssimetric(message interface{}, pKey publicKey, c net.Conn) {
	messageBytes, err := asn1.Marshal(message)
	if err != nil {
		log.Print(err)
		c.Close()
		return
	}

	pubKey := parsePublicKey(pKey)
	log.Println("MessageBytes:", messageBytes)
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
	var resultingKey rsa.PublicKey
	asn1.Unmarshal(pKey.KeyData, &resultingKey)
	return &resultingKey
}

func Sign(message interface{}, pKey *rsa.PrivateKey) ([]byte, error) {
	valueToBeSigned, _ := asn1.Marshal(message)
	hash := crypto.SHA256
	h := hash.New()
	h.Write(valueToBeSigned)
	hashed := h.Sum(nil)
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	signature, err := rsa.SignPSS(rand.Reader, pKey, hash, hashed, &opts)
	if err != nil {
		return make([]byte, 0), err
	}
	return signature, nil
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

	idp_private_key, _ := rsa.GenerateKey(rand.Reader, 2048)

	my_idp.Name = name
	my_idp.Port = port
	my_idp.Control = make(chan bool)
	my_idp.PrivateKey = idp_private_key
	go func() {
		err := my_idp.Listen()
		if err != nil {
			log.Println(err)
		}
		close(my_idp.Control)
	}()
	return my_idp
}
