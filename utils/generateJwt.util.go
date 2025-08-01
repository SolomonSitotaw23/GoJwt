package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MyCustomClaims struct {
	FirstName string `json:"firstName"`
	//add custom fields here
	jwt.RegisteredClaims
}

func GenerateJWT(userID uint) (string, error) {

	JWT_SECRET := []byte(os.Getenv("JWT_SECRET"))

	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // expiry of 15 minute short lived
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

func GenerateRefreshToken(userId uint) (string, error) {

	REFRESH_SECRET := []byte(os.Getenv("REFRESH_SECRET"))

	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // expiry of 7 days
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   strconv.Itoa(int(userId)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed_token, err := token.SignedString([]byte(REFRESH_SECRET))
	if err != nil {
		return "", err
	}
	return signed_token, nil
}
