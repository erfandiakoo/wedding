package main

import (
	"log"

	"github.com/erfandiakoo/wedding/router"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	app := fiber.New(fiber.Config{Prefork: false})
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,Head,Put,DELETE,PATH",
		AllowHeaders: "",
	}))

	router.SetupRoutes(app)

	err := app.Listen(":8181")
	if err != nil {
		log.Fatalln(err)
	}
}
