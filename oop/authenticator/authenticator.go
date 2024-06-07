package authenticator

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

type Authenticator struct {
	//data structure to store the private key
	//corresponding to all the RPs that the
	//authenticator has been registered on
	credentialsLog map[string]rsa.PrivateKey
}

func (auth Authenticator) actuallyCreateCredentials(RPid string) (pubKey rsa.PublicKey) {
	//generate private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	//generate public key
	pubKey = key.PublicKey

	//Store the private key
	auth.credentialsLog[RPid] = *key

	return
}

func (auth Authenticator) sign(RPid string, ciphertext []byte) []byte {
	//retrieve private key
	priv := auth.credentialsLog[RPid]

	//decrypt the cipher text
	challenge := DecryptWithPrivateKey(ciphertext, &priv)

	//hash the challenge
	challengeHash := sha512.New()
	_, err := challengeHash.Write(challenge)
	if err != nil {
		panic(err)
	}
	challengeHashSum := challengeHash.Sum(nil)

	//sign the hash
	signature, err := rsa.SignPSS(rand.Reader, &priv, crypto.SHA512, challengeHashSum, nil)
	if err != nil {
		panic(err)
	}

	return signature
}
