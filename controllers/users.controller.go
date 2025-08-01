package controllers

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/solomonsitotaw23/go_jwt/initializers"
	"github.com/solomonsitotaw23/go_jwt/models"
	"github.com/solomonsitotaw23/go_jwt/utils"
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
	if c.ShouldBindJSON(&body) != nil {
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
			"error": "Invalid Email or password",
		})
		return
	}

	// compare sent in pass with the saved password in the db

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or password",
		})
		return
	}

	// generate jwt token

	accessToken, err := utils.GenerateJWT(user.ID)

	if err != nil || accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "internal server error",
		})
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)

	if err != nil || refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "internal server error",
		})
	}

	// send it back
	// by creating a cookie

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", accessToken, 900, "", "", true, true)       //15 mins
	c.SetCookie("RefreshToken", refreshToken, 3600*24*7, "", "", true, true) // 7 days

	c.JSON(http.StatusOK, gin.H{
		"success": "logged in successfully",
	})
}

func Logout(c *gin.Context) {
	c.SetCookie("Authorization", "", -1, "", "", true, true)
	c.SetCookie("RefreshToken", "", -1, "", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "logged out",
	})
}

func Validate(c *gin.Context) {
	user, exists := c.Get("user")

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthenticated",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("RefreshToken")

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no refresh token"})
		return
	}

	token, err := jwt.ParseWithClaims(refreshToken, &utils.MyCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid refresh token",
		})
		return
	}

	claims := token.Claims.(*utils.MyCustomClaims)
	userID, _ := strconv.Atoi(claims.Subject)

	newAccessToken, err := utils.GenerateJWT(uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not generate new access token",
		})
		return
	}
	c.SetCookie("Authorization", newAccessToken, 900, "", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "access token refreshed",
	})
}
