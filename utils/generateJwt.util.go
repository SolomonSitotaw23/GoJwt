package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(userID uint) (string, error) {

	JWT_SECRET := []byte(os.Getenv("JWT_SECRET"))
	type MyCustomClaims struct {
		FirstName string `json:"firstName"`
		//add custom fields here
		jwt.RegisteredClaims
	}

	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // expiry of one day
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "go_jwt",
			Subject:   strconv.Itoa(int(userID)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed_token, err := token.SignedString(JWT_SECRET)

	if err != nil {
		return "", err
	}

	return signed_token, nil

}
