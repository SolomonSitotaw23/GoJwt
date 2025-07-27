package controllers

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/solomonsitotaw23/go_jwt/initializers"
	"github.com/solomonsitotaw23/go_jwt/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func SignUp(c *gin.Context) {

	var body models.UserData

	// get the email/password off the body
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}

	// hash the password

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to encrypt the password",
		})
		return
	}

	// create the user

	user := models.User{UserData: models.UserData{Email: body.Email, Password: string(hashedPassword)}}

	// Create a single record
	ctx := context.Background()
	err = gorm.G[models.User](initializers.DB).Create(ctx, &user) // pass pointer of data to Create

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create the user " + err.Error(),
		})
		return
	}
	// respond

	c.JSON(http.StatusOK, gin.H{
		"message": "user created",
	})
}

func Login(c *gin.Context) {

	var body models.UserData

	// get the email/password off the body
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}

	// look up requested user

	// Using string primary key
	ctx := context.Background()

	user, err := gorm.G[models.User](initializers.DB).Where("email = ?", body.Email).First(ctx)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect email address " + err.Error(),
		})
		return
	}

	// compare sent in pass with the saved password in the db

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password " + err.Error(),
		})
		return
	}

	// generate jwt token

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
			Subject:   strconv.Itoa(int(user.ID)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed_token, err := token.SignedString(JWT_SECRET)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error please try again",
		})
	}

	// send it back
	// by creating a cookie

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", signed_token, 3600*24, "", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"success": "logged in successfully",
	})
}

func Validate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "I'm logged in",
	})
}
