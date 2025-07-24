package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
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
