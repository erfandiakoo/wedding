package publicFunction

import "encoding/base64"

func InviteCodeGenerator(Phone string) string {
	inviteCode := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(Phone))
	return inviteCode
}
