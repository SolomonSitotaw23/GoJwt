package middleware

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/solomonsitotaw23/go_jwt/initializers"
	"github.com/solomonsitotaw23/go_jwt/models"
	"gorm.io/gorm"
)

func RequireAuth(c *gin.Context) {
	// get the cookie off req

	tokenString, err := c.Cookie("Authorization")

	if err != nil || tokenString == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// decode /validate it

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method :%v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || claims["sub"] == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "invalid token claims ",
		})
	}

	// find the user with token sub

	userId := claims["sub"]

	var user models.User

	user, err = gorm.G[models.User](initializers.DB).Where("id = ?", userId).First(c)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "user not found" + err.Error(),
		})
	}

	c.Set("user", user)

	// attach to req

	//continue
	c.Next()
}
