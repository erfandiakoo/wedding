package publicFunction

import (
	"regexp"
	"strings"
	"unicode"
)

func CleanUpPhone(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	value = NormalizePersian(value)
	value = DigitsToLatin(value)
	re := regexp.MustCompile(`^(?P<prefix>0098{1}|\+?98{1}|0{1})?(?P<phone>9{1}[0-9]{9})$`)
	if re.MatchString(value) {
		value = strings.TrimPrefix(value, "0098")
		value = strings.TrimPrefix(value, "+98")
		value = strings.TrimPrefix(value, "98")
		value = strings.TrimPrefix(value, "0")
		return value
	} else {
		return ""
	}
}

func DigitsToLatin(value string) string {
	var chars []rune
	for i := 0; i < len(value); i++ {
		if unicode.IsNumber(rune(value[i])) {
			chars = append(chars, rune(value[i]))
		} else {
			chars = append(chars, rune(value[i]))
		}
	}
	return string(chars)
}

func NormalizePersian(value string) string {
	value = strings.ReplaceAll(value, "\u1610", "\u1740")
	value = strings.ReplaceAll(value, "\u1603", "\u1705")
	return value
}
