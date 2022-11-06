package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	text    = "this is AES example"
	keySize = 32
)

var iv = func() []byte {
	return key(aes.BlockSize)
}()

func key(size int) []byte {
	key := make([]byte, size)
	rand.Read(key)
	return key
}

func encrypt(key, text []byte) ([]byte, error) {
	// get cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// get ctr
	ctr := cipher.NewCTR(block, iv)

	// encrypt
	enc := make([]byte, len(text))
	ctr.XORKeyStream(enc, text)

	return enc, nil
}

func decrypt(key, enc []byte) ([]byte, error) {
	// get cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// get ctr
	ctr := cipher.NewCTR(block, iv)

	// decrypt
	dec := make([]byte, len(enc))
	ctr.XORKeyStream(dec, enc)

	return dec, nil
}

func main() {
	fmt.Println("text:", text)

	k := key(keySize)
	fmt.Println("key:", hex.EncodeToString(k))
	fmt.Println("IV:", hex.EncodeToString(iv))

	enc, err := encrypt(k, []byte(text))
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("enc:", hex.EncodeToString(enc))

	dec, err := decrypt(k, enc)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("dec:", string(dec))
}
