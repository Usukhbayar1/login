package main

import (
	"github.com/gin-gonic/gin"
	"github.com/usukhbayar/login/controllers"
	"github.com/usukhbayar/login/initializers"
	"github.com/usukhbayar/login/middleware"
)

func init() {
	initializers.LoadEnvVariable()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}
func main() {

	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/forgotpass", controllers.ForgotPassword)
	r.PATCH("resetpass", controllers.ResetPassword)
	r.Run()
}
