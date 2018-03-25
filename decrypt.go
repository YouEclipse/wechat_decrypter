package wxdecrypter

import (
	"encoding/base64"
	"encoding/json"
)

// UserInfo 微信小程序用户信息
type UserInfo struct {
	OpenID    string `json:"openId"`
	Nickname  string `json:"nickName"`
	Gender    int    `json:"gender"`
	City      string `json:"city"`
	Province  string `json:"province"`
	Country   string `json:"country"`
	AvatarURL string `json:"avatarUrl"`
	UnionID   string `json:"unionId"`
	WaterMark struct {
		AppID     string `json:"appid"`
		Timestamp int64  `json:"timestamp"`
	} `json:"watermark"`
}

// Decrypt decrypt the crypted data and returns user obj and raw data
func Decrypt(cryptedData, sessionKey, iv string) (data *UserInfo, rawData []byte, err error) {
	var cryptedDataBytes, encryptedKeyBytes, ivBytes []byte
	cryptedDataBytes, err = base64.StdEncoding.DecodeString(cryptedData)
	if err != nil {
		return
	}
	encryptedKeyBytes, err = base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return
	}
	ivBytes, err = base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return
	}
	rawData, err = aesDecryptCBC(encryptedKeyBytes, ivBytes, cryptedDataBytes)
	if err != nil {
		return
	}
	data = new(UserInfo)
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return
	}
	return
}
