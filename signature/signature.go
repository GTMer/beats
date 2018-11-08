package signature


import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	// "errors"
	"fmt"
)

func RsaSignWithSha1Hex(data string, prvKey string) (string, error) {
	keyByts, err := hex.DecodeString(prvKey)
	if err != nil {
	   fmt.Println(err)
	   return "", err
	}
	// fmt.Println(keyByts)
	block,_ := pem.Decode(keyByts)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
	   fmt.Println("ParsePKCS8PrivateKey err", err)
	   return "", err
	}
	h := sha1.New()
	h.Write([]byte([]byte(data)))
	hash := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA1, hash[:])
	if err != nil {
	   fmt.Printf("Error from signing: %s\n", err)
	   return "", err
	}
	out := hex.EncodeToString(signature)
	return out, nil
 }

 func RsaVerySignWithSha1Base64(originalData, signData, pubKey string) error{
	sign, err := hex.DecodeString(signData)
	// sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
	   return err
	}
	public1, _ := base64.StdEncoding.DecodeString(pubKey)
	public, _ := pem.Decode(public1)
	pub, err := x509.ParsePKIXPublicKey(public.Bytes)
	if err != nil {
	   return err
	}
	hash := sha1.New()
	hash.Write([]byte(originalData))
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA1, hash.Sum(nil), sign)
 }