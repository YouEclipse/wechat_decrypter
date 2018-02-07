package wxdecrypter

import (
	"crypto/aes"
	"crypto/cipher"
)

func padding(cryptData []byte) []byte {
	length := len(cryptData)
	unpadding := int(cryptData[length-1])
	return cryptData[:(length - unpadding)]
}

func aesDecryptCBC(key, iv, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = padding(origData)
	return origData, nil
}
