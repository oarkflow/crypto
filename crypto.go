package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/oarkflow/crypto/utils"
)

func Encrypt(plainText string, secret string) (string, error) {
	data := utils.ToByte(plainText)
	key := utils.ToByte(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	ivHex := hex.EncodeToString(iv)
	encryptedData := base64.StdEncoding.EncodeToString(ciphertext[aes.BlockSize:])
	return ivHex + ":" + encryptedData, nil
}

func Decrypt(encrypted string, secret string) (string, error) {
	key := utils.ToByte(secret)
	parts := strings.Split(encrypted, ":")
	ivHex := parts[0]
	encryptedData := parts[1]

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return utils.FromByte(ciphertext), nil
}

/*
// Encrypt function
function encrypt(data) {
    const iv = CryptoJS.lib.WordArray.random(16); // Generate a random IV
    const encrypted = CryptoJS.AES.encrypt(data, key, { iv: iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding });
    const ivHex = CryptoJS.enc.Hex.stringify(iv);
    const encryptedData = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
    return ivHex + ":" + encryptedData;
}

// Decrypt function
function decrypt(encrypted) {
    const parts = encrypted.split(':');
    const ivHex = parts[0];
    const encryptedData = parts[1];
    const iv = CryptoJS.enc.Hex.parse(ivHex);
    const decrypted = CryptoJS.AES.decrypt(CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Base64.parse(encryptedData)
    }), key, { iv: iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding });
    return decrypted.toString(CryptoJS.enc.Utf8);
}
*/
