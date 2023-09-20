package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email              string
	Password           string
	PasswordResetToken string
}
type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}
type ResetPasswordInput struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}
