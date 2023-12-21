package router

import (
	"github.com/erfandiakoo/wedding/handler"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	api := app.Group("/v1")
	api.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.JSON("It Works!")
	})

	challenge := api.Group("/token")
	challenge.Post("/challenge", handler.ChallengeToken)
	challenge.Post("/verify", handler.Verify)
	challenge.Post("/refresh", handler.Refresh)
	challenge.Get("/logout", handler.LogOut)

	service := api.Group("service")
	service.Get("/landing", handler.GetLanding)
}
