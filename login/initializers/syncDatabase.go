package initializers

import "github.com/usukhbayar/login/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
