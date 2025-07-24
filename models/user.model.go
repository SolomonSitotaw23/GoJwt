package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	UserData
}

type UserData struct {
	Email    string `gorm:"unique"`
	Password string
}
