package middleware

import (
	"strings"

	"github.com/erfandiakoo/wedding/jwt"
	"github.com/gofiber/fiber/v2"
)

func Authenticator(ctx *fiber.Ctx) error {
	tokenClaims, err := jwt.Decrypt(ExtractToken(ctx), "app-pwa")
	if err != nil {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	}
	ctx.Locals("claims", tokenClaims)
	return ctx.Next()
}

// ExtractToken read the token from the request header
func ExtractToken(c *fiber.Ctx) string {
	bearToken := c.Get(fiber.HeaderAuthorization)
	if !strings.Contains(bearToken, "Bearer ") {
		return bearToken
	}
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
