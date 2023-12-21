package handler

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/erfandiakoo/wedding/util"

	"github.com/erfandiakoo/wedding/publicFunction"

	"github.com/erfandiakoo/wedding/model"

	"github.com/erfandiakoo/wedding/jwt"

	"github.com/erfandiakoo/wedding/config"
	"github.com/erfandiakoo/wedding/data"

	"github.com/gofiber/fiber/v2"
)

var RoleList []model.Role

func init() {
}

var Client model.Client

func ChallengeToken(c *fiber.Ctx) error {
	Input := new(model.ChallengeInput)
	if err := c.BodyParser(Input); err != nil {
		return err
	}
	if Input.Phone = publicFunction.CleanUpPhone(Input.Phone); Input.Phone == "" {
		return c.JSON(model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "شماره همراه اشتباه است.",
		})
	}
	if data.IsBlocked(Input.Phone) {
		return c.JSON(model.ResponseModel{
			Code:    500,
			Message: "شماره همراه اشتباه است.",
		})
	}
	Client, _ = data.CanLogin(c.Get(config.ClientKey))
	UserId := data.GetID(Input.Phone)
	fmt.Println(UserId)
	if !UserId.Valid {
		return RegisterChallenge(c, Input)
	}
	return LoginChallenge(c, Input)
}

func RegisterChallenge(c *fiber.Ctx, Input *model.ChallengeInput) (err error) {
	if data.IsOtpAttemptExceededAsync(Input) {
		return c.JSON(&model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "تعداد درخواست بیش از حد مجاز است.",
		})
	}

	salt, otp := publicFunction.GenerateOtp(publicFunction.StringGenerator(Input.Phone))
	util.SendOtpCode(Input.Phone, otp, Input.AppSignatureHash)

	var otpAttempt = model.OtpAttempt{
		Id:              publicFunction.IdGenerator.Generate().Int64(),
		CreationTimeUtc: time.Now().UTC(),
		UserId:          sql.NullInt64{},
		Phone:           Input.Phone,
		ClientId:        1,
		Salt:            salt,
		IssueTime:       time.Now().UTC(),
		ExpireTime:      time.Now().UTC().Add(120 * time.Second),
		UserIp:          c.IP(),
		UserAgent:       c.Get(config.UserAgent),
		OtpKind:         model.Kind(2),
	}

	if err = data.InsertOtpAttempt(&otpAttempt); err != nil {
		log.Println("InsertOtpAttempt error : ", err)
		return err
	}

	return c.JSON(model.ResponseModel{
		Data: map[string]interface{}{
			config.OtpId: strconv.FormatInt(otpAttempt.Id, 10),
		},
		Code: http.StatusOK,
	})
}

func LoginChallenge(c *fiber.Ctx, Input *model.ChallengeInput) (err error) {
	if data.IsOtpAttemptExceededAsync(Input) {
		return c.JSON(&model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "تعداد درخواست بیش از حد مجاز است.",
		})
	}
	user, _ := data.FindUserWithRoles(sql.NullInt64{}, Input.Phone)

	salt, otp := publicFunction.GenerateOtp(publicFunction.StringGenerator(Input.Phone))
	util.SendOtpCode(Input.Phone, otp, Input.AppSignatureHash)

	var otpAttempt = model.OtpAttempt{
		Id:              publicFunction.IdGenerator.Generate().Int64(),
		CreationTimeUtc: time.Now().UTC(),
		UserId: sql.NullInt64{
			Int64: user.Id,
		},
		Phone:      user.PhoneNumber,
		ClientId:   1,
		Salt:       salt,
		IssueTime:  time.Now().UTC(),
		ExpireTime: time.Now().UTC().Add(120 * time.Second),
		UserIp:     c.IP(),
		UserAgent:  c.Get(config.UserAgent),
		OtpKind:    model.Kind(2),
	}

	if err = data.InsertOtpAttempt(&otpAttempt); err != nil {
		log.Println("InsertOtpAttempt error : ", err)
		return err
	}

	return c.JSON(model.ResponseModel{
		Data: map[string]interface{}{
			config.OtpId: strconv.FormatInt(otpAttempt.Id, 10),
		},
		Code: 200,
	})
}

func Verify(c *fiber.Ctx) error {
	UserRole := new([]model.UserRole)
	Input := new(model.VerifyInput)
	if err := c.BodyParser(Input); err != nil {
		return err
	}
	if Input.Phone = publicFunction.CleanUpPhone(Input.Phone); Input.Phone == "" {
		return c.JSON(model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "شماره همراه اشتباه است.",
		})
	}
	if data.IsBlocked(Input.Phone) {
		return c.JSON(model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "شماره همراه اشتباه است.",
		})
	}
	var ok bool
	Client, ok = data.CanLogin("drzaji")
	fmt.Println(ok)

	if !ok {
		return c.JSON(model.ResponseModel{
			Data:    nil,
			Code:    500,
			Message: "اپلیکیشن شما ناشناخته است.",
		})
	}

	if strings.Contains(Client.AccessTokenLifeTime, " day") {
		Client.AccessTokenLifeTime = strings.ReplaceAll(Client.AccessTokenLifeTime, " days", "")
		Client.AccessTokenLifeTime = strings.ReplaceAll(Client.AccessTokenLifeTime, " day", "")
		a, _ := strconv.ParseInt(Client.AccessTokenLifeTime, 10, 64)
		Client.AccessTokenLifeTime = fmt.Sprintf("%vh", 24*a)
		log.Println("AccessTokenLifeTime : ", Client.AccessTokenLifeTime)
	}
	if strings.Contains(Client.RefreshTokenLifeTime, " day") {
		Client.RefreshTokenLifeTime = strings.ReplaceAll(Client.RefreshTokenLifeTime, " days", "")
		Client.RefreshTokenLifeTime = strings.ReplaceAll(Client.RefreshTokenLifeTime, " day", "")
		a, _ := strconv.ParseInt(Client.RefreshTokenLifeTime, 10, 64)
		Client.RefreshTokenLifeTime = fmt.Sprintf("%vh", 24*a)
		log.Println("RefreshTokenLifeTime : ", Client.RefreshTokenLifeTime)
	}

	log.Println(Input.OtpId)
	otpAttempt, err := data.FindOtpAttempt(Input.OtpId)
	if err != nil {
		return c.JSON(model.ResponseModel{
			Code:    500,
			Message: "درخواستی برای این کاربر پیدا نشد.",
		})
	}
	if otpAttempt == nil || otpAttempt.Phone != Input.Phone {
		return c.JSON(model.ResponseModel{
			Code:    500,
			Message: "درخواستی برای این کاربر پیدا نشد.",
		})
	}
	if otpAttempt.ExpireTime.Unix() < time.Now().UTC().Unix() {
		return c.JSON(model.ResponseModel{
			Code:    500,
			Message: "کد شما منقضی شده است.",
		})
	}
	if ok = publicFunction.IsOtpValid(Input.Code, otpAttempt.Salt); !ok {
		return c.JSON(model.ResponseModel{
			Code:    500,
			Message: "کد اشتباه است.",
		})
	}
	user, roles := data.FindUserWithRoles(otpAttempt.UserId, Input.Phone)
	if !otpAttempt.UserId.Valid && user.Id == 0 {
		user = &model.User{
			Id:            publicFunction.IdGenerator.Generate().Int64(),
			CreationTime:  time.Now().UTC(),
			PhoneNumber:   Input.Phone,
			LastLoginTime: time.Now().UTC(),
			UserRoles:     *UserRole,
			RefreshTokens: nil,
		}
		err = data.InsertUser(user)
		if err != nil {
			log.Fatalln("InsertUser error : ", err)
			return err
		}
		var userProfile = &model.UserProfile{
			Id:           publicFunction.IdGenerator.Generate().Int64(),
			CreationTime: time.Now().UTC(),
			UserId:       user.Id,
			InviteCode:   publicFunction.InviteCodeGenerator(user.PhoneNumber),
		}
		err = data.InsertUserProfile(userProfile)
		if err != nil {
			log.Fatalln("InsertUserProfile error : ", err)
			return err
		}
		otpAttempt.UserId = sql.NullInt64{
			Int64: user.Id,
			Valid: true,
		}
		otpAttempt.ModificationTimeUtc = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		err = data.UpdateOtpAttemptUserId(otpAttempt)
		if err != nil {
			log.Fatalln("UpdateOtpAttemptUserId : ", err)
		}
	}
	user.LastLoginTime = time.Now().UTC()
	if len(Client.DefaultRoles) > 0 {
		a := strings.Split(Client.DefaultRoles, ",")
		for _, defaultRole := range a {
			for _, m := range RoleList {
				if defaultRole == m.Name {
					*UserRole = append(*UserRole, model.UserRole{
						UserId: user.Id,
						RoleId: m.Id.Int64,
					})
				}
			}
		}
	}
	var refresh = jwt.GenerateRefreshToken()
	d, err := time.ParseDuration(Client.RefreshTokenLifeTime)
	if err != nil {
		log.Fatalln("ParseDuration error : ", err)
	}
	log.Println("Duration of refresh token life time : ", d)
	var refreshToken = &model.RefreshToken{}
	refreshtokenid := sql.NullInt64{
		Int64: publicFunction.IdGenerator.Generate().Int64(),
		Valid: true,
	}
	refreshToken = &model.RefreshToken{
		Id:           refreshtokenid.Int64,
		CreationTime: time.Now().UTC(),
		ModifyTime: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
		UserId:     user.Id,
		ClientId:   Client.Id,
		Token:      refresh,
		IssueTime:  time.Now().UTC(),
		ExpireTime: time.Now().UTC().Add(d),
	}

	d, err = time.ParseDuration(Client.AccessTokenLifeTime)
	if err != nil {
		log.Fatalln("ParseDuration error : ", err)
	}

	var accessToken = &model.AccessToken{
		Id:             publicFunction.IdGenerator.Generate().Int64(),
		CreationTime:   time.Now().UTC(),
		RefreshTokenId: refreshToken.Id,
		IssueTime:      time.Now().UTC(),
		ExpireTime:     time.Now().UTC().Add(d),
	}

	var Tokenclaim = &model.TokenClaim{
		TokenId:        strconv.FormatInt(accessToken.Id, 10),
		IssuedAt:       time.Now().UTC().String(),
		UserId:         strconv.FormatInt(user.Id, 10),
		Phone:          user.PhoneNumber,
		RefreshVersion: strconv.FormatInt(refreshToken.Id, 10),
		EulaVersion:    config.EulaVersion,
		Issuer:         "",
		LifeTime:       Client.AccessTokenLifeTime,
		AccessVersion:  strconv.FormatInt(accessToken.Id, 10),
		Roles:          roles,
		Audience:       Client.Audience,
		Expires:        strconv.FormatInt(time.Now().UTC().Add(d).Unix(), 10),
		NotBefore:      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	}

	var access = jwt.GenerateToken(Tokenclaim, &Client)
	accessToken.Token = access
	err = data.InsertRefresh(refreshToken)
	if err != nil {
		log.Println("InsertRefresh error : ", err)
		return err
	}
	err = data.InsertAccess(accessToken)
	if err != nil {
		log.Println("InsertAccess error : ", err)
		return err
	}

	return c.JSON(&model.ResponseModel{
		Data: map[string]interface{}{
			"accessToken":  access,
			"refreshToken": refresh,
		},
		Code: 200,
	})

}

func LogOut(ctx *fiber.Ctx) error {
	tokenClaims, err := jwt.Decrypt(ExtractToken(ctx), "drzaji")
	if err != nil {
		return ctx.SendStatus(http.StatusUnauthorized)
	}
	if !tokenClaims.IsLifeTimeValid() {
		if err != nil {
			return ctx.SendStatus(http.StatusUnauthorized)
		}
	}
	err = data.LogOut(tokenClaims)

	if err != nil {
		log.Println(err)
		return ctx.JSON(&model.ResponseModel{
			Data:    map[string]interface{}{"value": false},
			Code:    500,
			Message: "failed",
		})
	}
	return ctx.JSON(&model.ResponseModel{
		Data: map[string]interface{}{"value": true},
		Code: 200,
	})
}

func Refresh(ctx *fiber.Ctx) error {
	var ok bool
	Client, ok = data.CanLogin(ctx.Get(config.ClientKey))
	if !ok {
		return ctx.JSON(model.ResponseModel{
			Code:    500,
			Message: "اپلیکیشن شما ناشناخته است.",
		})
	}

	Input := new(model.RefreshInput)
	if err := ctx.BodyParser(Input); err != nil {
		return err
	}

	tokenClaims, err := jwt.Decrypt(Input.AccessToken, ctx.Get(config.ClientKey))
	if err != nil {
		return ctx.SendStatus(http.StatusUnauthorized)
	}

	if data.IsBlocked(tokenClaims.Phone) {
		return ctx.JSON(model.ResponseModel{
			Code:    500,
			Message: "شماره همراه اشتباه است.",
		})
	}

	userid, _ := strconv.ParseInt(tokenClaims.UserId, 10, 64)
	user, roles := data.FindUserWithRoles(sql.NullInt64{Int64: userid, Valid: true}, tokenClaims.Phone)
	if user == nil {
		return ctx.JSON(model.ResponseModel{
			Code:    500,
			Message: "کاربر مورد نظر پیدا نشد.",
		})
	}

	DeviceId, err := strconv.ParseInt(tokenClaims.DeviceId, 10, 64)
	if err != nil {
		log.Fatalln("ParseInt error of tokenClaims.DeviceId : ", err)
	}
	RefreshTokenModel, err := data.FindRefreshToken(Client.Id, user.Id, DeviceId, Input.RefreshToken)
	if err != nil {
		log.Fatalln("FindRefreshToken error : ", err)
	}
	if RefreshTokenModel.Token == "" {
		return ctx.JSON(model.ResponseModel{
			Code:    500,
			Message: "درخواستی برای این کاربر پیدا نشد.",
		})
	}

	if RefreshTokenModel.ExpireTime.Unix() < time.Now().UTC().Unix() || RefreshTokenModel.IsRevoked {
		return ctx.JSON(model.ResponseModel{
			Code:    500,
			Message: "لطفا مجددا وارد شوید.",
		})
	}

	if strings.Contains(Client.AccessTokenLifeTime, " day") {
		Client.AccessTokenLifeTime = strings.ReplaceAll(Client.AccessTokenLifeTime, " days", "")
		Client.AccessTokenLifeTime = strings.ReplaceAll(Client.AccessTokenLifeTime, " day", "")
		a, _ := strconv.ParseInt(Client.AccessTokenLifeTime, 10, 64)
		Client.AccessTokenLifeTime = fmt.Sprintf("%vh", 24*a)
		log.Println("AccessTokenLifeTime : ", Client.AccessTokenLifeTime)
	}
	if strings.Contains(Client.RefreshTokenLifeTime, " day") {
		Client.RefreshTokenLifeTime = strings.ReplaceAll(Client.RefreshTokenLifeTime, " days", "")
		Client.RefreshTokenLifeTime = strings.ReplaceAll(Client.RefreshTokenLifeTime, " day", "")
		a, _ := strconv.ParseInt(Client.RefreshTokenLifeTime, 10, 64)
		Client.RefreshTokenLifeTime = fmt.Sprintf("%vh", 24*a)
		log.Println("RefreshTokenLifeTime : ", Client.RefreshTokenLifeTime)
	}

	var refresh = jwt.GenerateRefreshToken()
	d, err := time.ParseDuration(Client.RefreshTokenLifeTime)
	if err != nil {
		log.Fatalln("ParseDuration error : ", err)
	}
	log.Println("Duration of refresh token life time : ", d)
	var refreshToken = &model.RefreshToken{}

	refreshToken = &model.RefreshToken{
		Id:           sql.NullInt64{Int64: publicFunction.IdGenerator.Generate().Int64()}.Int64,
		CreationTime: time.Now().UTC(),
		UserId:       user.Id,
		ClientId:     Client.Id,
		Token:        refresh,
		IssueTime:    time.Now().UTC(),
		ExpireTime:   time.Now().UTC().Add(d),
	}

	d, err = time.ParseDuration(Client.AccessTokenLifeTime)
	if err != nil {
		log.Fatalln("ParseDuration error : ", err)
	}

	var accessToken = &model.AccessToken{
		Id:             publicFunction.IdGenerator.Generate().Int64(),
		CreationTime:   time.Now().UTC(),
		RefreshTokenId: refreshToken.Id,
		IssueTime:      time.Now().UTC(),
		ExpireTime:     time.Now().UTC().Add(d),
	}

	var Tokenclaim = &model.TokenClaim{
		TokenId:        strconv.FormatInt(accessToken.Id, 10),
		IssuedAt:       time.Now().UTC().String(),
		UserId:         strconv.FormatInt(user.Id, 10),
		Phone:          user.PhoneNumber,
		RefreshVersion: strconv.FormatInt(refreshToken.Id, 10),
		EulaVersion:    config.EulaVersion,
		Issuer:         Client.Issuer,
		LifeTime:       Client.AccessTokenLifeTime,
		AccessVersion:  strconv.FormatInt(accessToken.Id, 10),
		AppSource:      Client.Issuer,
		Roles:          roles,
		Audience:       Client.Audience,
		Expires:        strconv.FormatInt(time.Now().UTC().Add(d).Unix(), 10),
		NotBefore:      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	}

	var access = jwt.GenerateToken(Tokenclaim, &Client)
	accessToken.Token = access
	err = data.InsertRefresh(refreshToken)
	if err != nil {
		log.Fatalln("InsertRefresh error : ", err)
		return err
	}
	err = data.InsertAccess(accessToken)
	if err != nil {
		log.Fatalln("InsertAccess error : ", err)
		return err
	}
	return ctx.JSON(&model.ResponseModel{
		Data: map[string]interface{}{
			"accessToken":  access,
			"refreshToken": refresh,
		},
		Code: 200,
	})

}

func TestToken(c *fiber.Ctx) error {
	token, err := jwt.Decrypt(ExtractToken(c), c.Get(config.ClientKey))
	if err != nil {
		return c.SendStatus(http.StatusUnauthorized)
	}
	fmt.Println(token)
	return c.JSON(&model.ResponseModel{
		Data: map[string]interface{}{"tokenClaims": token},
		Code: 200,
	})
}

// ExtractToken read the token from the request header
func ExtractToken(c *fiber.Ctx) string {
	bearToken := c.Get(config.Authorization)
	if !strings.Contains(bearToken, "Bearer ") {
		return bearToken
	}
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
