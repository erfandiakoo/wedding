package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/erfandiakoo/wedding/data"

	"github.com/erfandiakoo/wedding/config"

	"github.com/erfandiakoo/wedding/model"

	jose "github.com/dvsekhvalnov/jose2go"
)

var ClientsTable []model.Client

func init() {
	data.Initial()
	time.Sleep(2 * time.Second)
	Initial()

}

func Initial() {
	var OK bool

	ClientsTable, OK = data.GetClientsTable()
	if !OK {
		log.Println("Client table does not exist in cache")
	}
	log.Println(ClientsTable)
	for _, client := range ClientsTable {
		var Key [][]byte
		e, s := SigningAndEncryptionKeyFinder(client.Issuer)
		Key = append(Key, e, s)
		data.Cache.Set(client.Issuer, Key, 1)
	}
}
func Decrypt(token, issuer string) (tokenClaims *model.TokenClaim, err error) {
	if token == "" {
		return nil, fmt.Errorf("no valid token")
	}
	return decrypt(token, issuer)
}

func decrypt(token, issuer string) (tokenClaims *model.TokenClaim, err error) {
	var newVersion bool
	var signingKey, encryptionKey []byte
	key, found := data.Cache.Get(issuer)
	if !found {
		return nil, fmt.Errorf("the %s issuer does not exist", issuer)
	}

	a, _, err := jose.Decode(token, func(header map[string]interface{}, payload string) interface{} {
		if header[config.IssuerHeader] != issuer {
			return nil
		}
		encryptionKey, signingKey = (key).([][]byte)[config.EncryptingKeyIndex], (key).([][]byte)[config.SigningKeyIndex]
		if i, ok := header[config.TokenVersion]; ok {
			if i.(string) == "v1" {
				newVersion = true
				return encryptionKey
			}
		}
		token, _, err = jose.Decode(token, encryptionKey)
		if err != nil {
			log.Println("error decrypt:", err, "\n", token)
			return encryptionKey
		}
		return encryptionKey
	})
	if !newVersion {
		tokenClaims, err = decode(token, signingKey)
		log.Println("error decrypt:", err)
		return
	}
	//tokenClaims, err = verifyToken(a, issuer)
	if err != nil {
		log.Println(err)
	}
	tokenClaims, err = WrapTokenString(a)
	if err != nil {
		log.Println("WrapTokenString : \n", err)
	}
	return
}

func decode(decryptedToken string, SigningKey []byte) (tokenClaims *model.TokenClaim, err error) {
	if len(decryptedToken) <= 0 {
		return nil, fmt.Errorf("token is invalidd %s", decryptedToken)
	}
	//return ExtractTokenMetadata(decryptedToken[3:], SigningKey)
	return
}

func SigningAndEncryptionKeyFinder(h string) (encryptingKey, signingKey []byte) {
	var err error
	ClientsTable, _ = data.GetClientsTable()
	for _, client := range ClientsTable {
		if h == client.Issuer {
			signingKey, err = base64.StdEncoding.DecodeString(client.SigningKey)
			if err != nil {
				return nil, nil
			}
			encryptingKey, err = base64.StdEncoding.DecodeString(client.EncryptingKey)
			if err != nil {
				return nil, nil
			}
			return
		}
	}
	return
}

func GenerateToken(access *model.TokenClaim, Client *model.Client) string {

	encryptingKey, err := base64.StdEncoding.DecodeString(Client.EncryptingKey)
	EncryptedToken, err := jose.Encrypt(access.String(), Client.Alg, Client.Enc, encryptingKey, jose.Zip(jose.DEF), jose.Headers(map[string]interface{}{"typ": "JWT", "tc:iss": Client.Issuer, config.TokenVersion: "v1"}))
	if err != nil {
		log.Println(err)
		return ""
	}
	return EncryptedToken
}

func GenerateRefreshToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func WrapTokenString(a string) (tokenClaims *model.TokenClaim, err error) {
	tokenClaims = new(model.TokenClaim)
	a = "{" + a + "}"
	a = strings.ReplaceAll(a, "TokenId", "\n"+`"TokenId"`)
	a = strings.ReplaceAll(a, "IssuedAt", ",\n"+`"IssuedAt"`)
	a = strings.ReplaceAll(a, "UserId", ",\n"+`"UserId"`)
	a = strings.ReplaceAll(a, "Phone", ",\n"+`"Phone"`)
	a = strings.ReplaceAll(a, "RefreshVersion", ",\n"+`"RefreshVersion"`)
	a = strings.ReplaceAll(a, "EulaVersion", ",\n"+`"EulaVersion"`)
	a = strings.ReplaceAll(a, "LifeTime", ",\n"+`"LifeTime"`)
	a = strings.ReplaceAll(a, "AccessVersion", ",\n"+`"AccessVersion"`)
	a = strings.ReplaceAll(a, "DeviceId", ",\n"+`"DeviceId"`)
	a = strings.ReplaceAll(a, "Audience", ",\n"+`"Audience"`)
	a = strings.ReplaceAll(a, "Expires", ",\n"+`"Expires"`)
	a = strings.ReplaceAll(a, "NotBefore", ",\n"+`"NotBefore"`)
	a = strings.ReplaceAll(a, "Issuer", ",\n"+`"Issuer"`)
	a = strings.ReplaceAll(a, "AppSource", ",\n"+`"AppSource"`)
	a = strings.ReplaceAll(a, "Roles", ",\n"+`"Roles"`)
	a = strings.ReplaceAll(a, "CallBackId", ",\n"+`"CallBackId"`)
	a = strings.ReplaceAll(a, "SessionId", ",\n"+`"SessionId"`)
	//a = strings.ReplaceAll(a,"  "," ,\n")

	err = json.Unmarshal([]byte(a), &tokenClaims)
	return
}
