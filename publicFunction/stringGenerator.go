package publicFunction

import (
	"crypto/rand"
)

func StringGenerator(c string) (str string) {
	b := make([]byte, len(c))
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return string(b)
}
