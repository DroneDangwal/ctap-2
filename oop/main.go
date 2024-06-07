package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	auth "oop/authenticator"
)

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func main() {
	a := auth.Authenticator{}

	//register a relying party and get the public key
	publickey := auth.Authenticator.actuallyCreateCredentials(a, "www.ggogle.com")

	//generate cipher text
	challenge := "show me who you are"
	challengeHash := sha512.New()
	_, err := challengeHash.Write([]byte(challenge))
	if err != nil {
		panic(err)
	}
	challengeHashSum := challengeHash.Sum(nil)

	cipher := EncryptWithPublicKey([]byte(challenge), &publickey)

	//send to a and receive back the signed challenge
	sign := a.sign("www.ggogle.com", cipher)

	//decrypt and verify
	erro := rsa.VerifyPSS(&publickey, crypto.SHA512, challengeHashSum, sign, nil)
	if erro != nil {
		fmt.Println("wrong liar")
		return
	}
	fmt.Println("Successful login")

}
