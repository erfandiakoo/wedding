package util

import (
	"fmt"

	"github.com/kavenegar/kavenegar-go"
)

var apiToken = "524C625439335A5A616C77594A4239794853574B4A64304E496772775A4F616E5073666D4D6578727277773D"

func SendOtpCode(Phone string, OtpCode string, AppSignatureHash string) {
	SendLookup(Phone, OtpCode, "app-verify")
}

func SendLookup(receptor string, token string, template string) {
	api := kavenegar.New(apiToken)
	params := &kavenegar.VerifyLookupParam{}
	if res, err := api.Verify.Lookup(receptor, template, token, params); err != nil {
		switch err := err.(type) {
		case *kavenegar.APIError:
			fmt.Println(err.Error())
		case *kavenegar.HTTPError:
			fmt.Println(err.Error())
		default:
			fmt.Println(err.Error())
		}
	} else {
		fmt.Println("MessageID 	= ", res.MessageID)
		fmt.Println("Status    	= ", res.Status)
	}
}
