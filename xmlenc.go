package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
)

func DecryptElement(src *etree.Element, sk *rsa.PrivateKey) (*etree.Element, error) {
	// Do some preliminary checks.
	// Warning: these are very specific and should be expanded for more support,
	// at some point.
	if src.Tag != "EncryptedData" {
		return nil, errors.New("xmlenc: element to decrypt must be EncryptedData, not " + src.Tag)
	}
	if src.SelectAttrValue("Type", "") != "http://www.w3.org/2001/04/xmlenc#Element" {
		return nil, errors.New("xmlenc: EncryptedData is not an element but " + src.SelectAttrValue("Type", ""))
	}
	encMethod := src.FindElement("EncryptionMethod").SelectAttrValue("Algorithm", "")
	if encMethod != "http://www.w3.org/2001/04/xmlenc#aes256-cbc" {
		return nil, errors.New("xmlenc: unsupported symmetric key algorithm: " + encMethod)
	}
	pubkeyAlgo := src.FindElement("KeyInfo/EncryptedKey/EncryptionMethod").SelectAttrValue("Algorithm", "")
	if pubkeyAlgo != "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" {
		return nil, errors.New("xmlenc: unsupported public key algorithm: " + pubkeyAlgo)
	}
	digestMethod := src.FindElement("KeyInfo/EncryptedKey/EncryptionMethod/DigestMethod").SelectAttrValue("Algorithm", "")
	if digestMethod != "http://www.w3.org/2000/09/xmldsig#sha1" {
		return nil, errors.New("xmlenc: unsupported digest method: " + digestMethod)
	}

	// Decode the ciphertext from base64.

	pubkeyCiphertextB64 := src.FindElement("KeyInfo/EncryptedKey/CipherData/CipherValue").Text()
	pubkeyCiphertext, err := base64.StdEncoding.DecodeString(pubkeyCiphertextB64)
	if err != nil {
		return nil, err
	}

	ciphertextB64 := src.FindElement("CipherData/CipherValue").Text()
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}

	// Decrypt the key (which is encrypted using RSA).
	key, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, sk, pubkeyCiphertext, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext with AES-CBC.
	// Note: this is not secure against padding oracles! The ciphertext MUST be
	// verified before decryption!
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Strip the padding.
	paddingLen := data[len(data)-1]
	if paddingLen >= aes.BlockSize {
		return nil, errors.New("xmlenc: invalid padding")
	}
	data = data[:len(data)-int(paddingLen)]

	// Parse the resulting element.
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &doc.Element, nil
}
