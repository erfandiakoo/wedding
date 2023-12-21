package handler

import "github.com/gofiber/fiber/v2"

func GetLanding(c *fiber.Ctx) (err error) {
	return c.JSONP("Hello")
}
