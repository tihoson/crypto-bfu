package main

import (
	"encoding/hex"
	"fmt"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

const (
	message      = "HMAC example"
	wrongMeesage = "not HMAC example"
	keySize      = 32
)

func keyGen(size int) []byte {
	key := make([]byte, size)
	rand.Read(key)
	return key
}

func sign(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func verify(key, message, messageMAC []byte) bool {
	expected := sign(key, message)
	return hmac.Equal(expected, messageMAC)
}

func main() {
	fmt.Println("message:", message)

	key := keyGen(keySize)
	fmt.Println("key:", hex.EncodeToString(key))

	mac := sign(key, []byte(message))
	fmt.Println("mac:", hex.EncodeToString(mac))

	fmt.Println("verify:", verify(key, []byte(message), mac))
	fmt.Println("verify with wrong text:", verify(key, []byte(wrongMeesage), mac))
	fmt.Println("verify with wrong key:", verify(keyGen(keySize), []byte(message), mac))
	fmt.Println("verify with wrong mac:", verify(key, []byte(message), keyGen(keySize)))
}
