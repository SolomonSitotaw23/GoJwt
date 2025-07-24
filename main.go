package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/solomonsitotaw23/go_jwt/initializers"
)

func init() {
	log.Println("initialization started")
	initializers.LoadEnvVariables()
	log.Println("initialization finished")
}

func main() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.Run()
}
