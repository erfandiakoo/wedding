package data

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/erfandiakoo/wedding/model"
)

var (
	dbUrl string
	db    *gorm.DB
	err   error
)

func init() {
	dbUrl = "host=5.34.202.220 user=atron password=Rp@19088 dbname=wedding port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dbUrl))
	if err != nil {
		log.Println(err)
		return
	}
	//err = db.Migrator().DropTable(&model.GiftCode{})
	err = db.AutoMigrate(&model.Client{}, &model.User{}, &model.Role{}, &model.OtpAttempt{}, &model.UserRole{}, &model.BlockedPhone{}, &model.AccessToken{}, &model.RefreshToken{}, &model.UserProfile{}, &model.UserReserve{}, &model.Services{})
	if err != nil {
		log.Fatalln("Auto migrating error : ", err)
	}
}

func Initial() {
	ok := SetClientTable(getClientsTable())
	if !ok {
		log.Println("Cannot set the client table")
	}
}
func getClientsTable() (A []model.Client) {
	err = db.Model(&model.Client{}).Order(`"Id" desc`).Find(&A).Error
	if err != nil {
		log.Println(err)
		return nil
	}
	log.Println("Client Table : \n", A)
	return
}

func FindClient(Issuer string) (ClientTable model.Client) {
	a, _ := GetClientsTable()
	for _, client := range a {
		if Issuer == client.Issuer {
			return client
		}
	}
	return
}

func IsBlocked(Number string) bool {
	Blocked := new([]model.BlockedPhone)
	err = db.Where(`"Number" = ?`, Number).Find(Blocked).Error
	if err != nil {
		log.Print(err)
		return false
	}
	log.Println(Blocked)
	for _, blocked := range *Blocked {
		if blocked.Number == Number {
			log.Println(true, Number)
			return true
		}
	}
	return false
}

func GetID(Phone string) sql.NullInt64 {
	var otpAttempts model.OtpAttempt
	err = db.Where(`"Phone" = ?`, Phone).Find(&otpAttempts).Error
	if err != nil {
		log.Println(err)
		return sql.NullInt64{}
	}
	return otpAttempts.UserId

}

func IsOtpAttemptExceededAsync(Model *model.ChallengeInput) bool {
	var limitationTime = time.Unix(time.Now().UTC().Unix()-int64(2*time.Minute.Seconds()), 0)
	var AttemptLimitationCount int64 = 10
	otp := new(model.OtpAttempt)
	var count int64
	err = db.Model(&model.OtpAttempt{}).Where(`"Phone" = ? AND "IssueTime" >= ?`, Model.Phone, limitationTime).Count(&count).Error
	if err != nil {
		log.Println(err)
	}
	err = db.Where(`"Phone" = ?`, Model.Phone).Order(`"IssueTime"`).Find(&otp).Error
	if err != nil {
		log.Println("IssueTime", err)
	}
	if count > AttemptLimitationCount {
		return true
	}
	if (time.Unix(time.Now().UTC().Unix()-int64(3*time.Minute.Seconds()), 0).Unix()) < otp.IssueTime.Unix() {
		return true
	}
	return false
}

func FindUserWithRoles(UserId sql.NullInt64, Phone string) (*model.User, []string) {
	user := new(model.User)
	var role []string
	var roles []model.Role

	err = db.Preload("UserRoles").Model(user).Where(`"PhoneNumber" = ?`, Phone).Find(user).Error
	log.Println("user entities:", user, "err:", err)
	log.Println("user id : ", user.Id)
	if user.Id != 0 {

		err = db.Preload(`"Roles"."Name"`).Model(&model.Role{}).Where(`"Id" = ?`, -12).Find(&roles).Error
		if err != nil {
			log.Println("user roles error : ", err)
		}
		fmt.Println("user roles ", roles)
	}
	if UserId.Valid {
		err = db.Preload("Roles.Name").Model(&model.Role{}).Where(model.Role{}.Id, user.UserRoles).Find(&roles).Error
		if err != nil {
			log.Println("roles name error : ", err)
		}
		fmt.Println("b:", roles[0].Name)
	}
	return user, role
}

func CheckInviteCode(inviteCode string) bool {
	var inviterUserProfile string
	if inviteCode == "" {
		return true
	}
	err = db.Table(model.UserProfile{}.TableName()).Where(`"InviteCode" = ?`).First(&inviterUserProfile).Error
	if err != nil {
		log.Println("user InviteCode error : ", err)
	}
	return inviterUserProfile != ""
}

func InsertOtpAttempt(Model *model.OtpAttempt) (err error) {
	err = db.Create(Model).Error
	return
}

func FindOtpAttempt(OtpId int64) (OtpAttempt *model.OtpAttempt, err error) {
	OtpAttempt = new(model.OtpAttempt)
	err = db.Where(`"Id" = ?`, OtpId).Find(OtpAttempt).Error
	return
}

func FindPhone(UserId int64) string {
	var user model.User
	err = db.First(&user, UserId).Error

	return user.PhoneNumber
}

func CheckAdminRole(UserId int64) bool {
	var roles model.UserRole
	err = db.First(&roles, UserId).Error

	return roles.RoleId == 2
}

func UpdateOtpAttemptUserId(Model *model.OtpAttempt) (err error) {
	err = db.Where(`"Id" = ?`, Model.Id).UpdateColumns(Model).Error
	return err
}

func InsertUser(Model *model.User) (err error) {
	err = db.Create(Model).Error
	return
}

func InsertUserProfile(Model *model.UserProfile) (err error) {
	err = db.Create(Model).Error
	return
}
func InsertRefresh(Model *model.RefreshToken) (err error) {
	err = db.Create(Model).Error
	return
}

func InsertAccess(Model *model.AccessToken) (err error) {
	err = db.Create(Model).Error
	return
}

func GetUserProfiles() (Model []model.GiftCode, err error) {
	err = db.
		Model(&model.UserProfile{}).
		Scan(&Model).
		Error
	return
}

func LogOut(Model *model.TokenClaim) (err error) {
	var accessToken model.AccessToken
	accId, _ := strconv.Atoi(Model.AccessVersion)
	err = db.Where(`"AccessTokens"."Id" = ?`, accId).Find(&accessToken).Error
	log.Println("Loaded accessToken entity : ", accessToken)
	err = db.Where(`"RefreshTokens"."Id" = ?`, accessToken.RefreshTokenId).Find(&accessToken.RefreshToken).Error
	log.Println("Loaded accessToken entity : ", accessToken)
	accessToken.IsRevoked = true
	accessToken.RevokeTime = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	accessToken.ModifyTime = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	accessToken.RefreshToken.IsRevoked = true
	accessToken.RefreshToken.RevokeTime = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	accessToken.RefreshToken.ModifyTime = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	err = db.Save(&accessToken).Error
	if err != nil {
		log.Fatalln("Error of Saving accessToken for LogOut : ", err)
	}
	err = db.Save(&accessToken.RefreshToken).Error
	if err != nil {
		log.Fatalln("Error of Saving accessToken for LogOut : ", err)
	}

	return err
}

func FindRefreshToken(ClientId int64, UserId int64, DeviceId int64, RefreshToken string) (Model *model.RefreshToken, err error) {
	Model = new(model.RefreshToken)
	err = db.Where(`"ClientId" = ? AND "UserId" = ? AND "DeviceId" = ? AND "IsRevoked" = false`, ClientId, UserId, DeviceId).First(&Model).Error
	log.Println("Found RefreshToken : ", Model)
	return
}

func UpdateAvatarFileId(UserId int64, FileId int64) (err error) {
	var user model.User
	err = db.Where(`"Id" = ?`).Find(&user).Error
	if err != nil {
		log.Println(err)
		return err
	}
	if user.Id != UserId {
		return fmt.Errorf("user does not exist")
	}
	var userProfile = &model.UserProfile{
		ModifyTime: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
		ProfileImageFileId: FileId,
	}
	err = db.Where(`"UserId" = ?`, UserId).Updates(&userProfile).Error
	if err != nil {
		log.Println(err)
		return err
	}
	return
}
