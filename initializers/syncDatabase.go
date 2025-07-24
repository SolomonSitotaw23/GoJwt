package initializers

import "github.com/solomonsitotaw23/go_jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
