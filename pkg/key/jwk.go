package key

import (
	"encoding/base64"
)

func GetRSAPublicKeyJWK(kid string) map[string]string {
	pub := GetPublicKey()
	if pub == nil {
		return nil
	}
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E)),
	}
}

func bigIntToBytes(e int) []byte {
	b := make([]byte, 0)
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
