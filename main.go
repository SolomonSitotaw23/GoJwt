package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/solomonsitotaw23/go_jwt/controllers"
	"github.com/solomonsitotaw23/go_jwt/initializers"
	"github.com/solomonsitotaw23/go_jwt/middleware"
)

func init() {
	log.Println("initialization started")
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
	log.Println("initialization finished")
}

func main() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	router.POST("/signup", controllers.SignUp)
	router.POST("/login", controllers.Login)
	router.POST("/logout", controllers.Logout)
	router.GET("/validate", middleware.RequireAuth, controllers.Validate)
	router.POST("/refresh", controllers.Refresh)

	router.Run()
}
