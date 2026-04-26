package mfa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
