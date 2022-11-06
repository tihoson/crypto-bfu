package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
)

const (
	keySize = 4096
	message = "very secret"
)

func keyGen(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey, nil
}

func sign(private *rsa.PrivateKey, msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)

	signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func verify(public *rsa.PublicKey, msg, signature []byte) error {
	hashed := sha256.Sum256(msg)

	return rsa.VerifyPSS(
		public,
		crypto.SHA256,
		hashed[:],
		signature,
		nil,
	)
}

func privateToPem(private *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA private",
			Bytes: x509.MarshalPKCS1PrivateKey(private),
		},
	)
}

func publicToPem(public *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA public",
			Bytes: x509.MarshalPKCS1PublicKey(public),
		},
	)
}

func main() {
	fmt.Println("message:", message)

	private, public, err := keyGen(keySize)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("private:", hex.EncodeToString(privateToPem(private)))
	fmt.Println("public:", hex.EncodeToString(publicToPem(public)))

	signature, err := sign(private, []byte(message))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature:", hex.EncodeToString(signature))

	// valid signature
	if err := verify(public, []byte(message), signature); err == nil {
		fmt.Println("verified")
	} else {
		log.Fatal(err)
	}

	// invalid signature
	if err := verify(public, []byte(message), []byte(message)); err != nil {
		fmt.Println("invalid signature")
	} else {
		log.Fatal(err)
	}
}
