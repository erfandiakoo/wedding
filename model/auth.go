package model

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	UserCities    = "UserCities"
	GiftCodes     = "GiftCodes"
	UserProfiles  = "UserProfiles"
	Devices       = "Devices"
	AccessTokens  = "AccessTokens"
	RefreshTokens = "RefreshTokens"
	BlockedPhones = "BlockedPhones"
	Clients       = "Clients"
	OtpAttempts   = "OtpAttempts"
	UserRoles     = "UserRoles"
	Users         = "Users"
	Roles         = "Roles"
)

var Domain string

type ChallengeInput struct {
	Phone            string `json:"phone"`
	AppSignatureHash string `json:"appSignatureHash"`
}

type VerifyInput struct {
	Phone          string `json:"phone"`
	Code           string `json:"code"`
	OtpId          int64  `json:"otpId,string"`
	FirebaseId     string `json:"firebaseId"`
	PhoneModel     string `json:"phoneModel"`
	AndroidVersion string `json:"androidVersion"`
	ScreenSize     string `json:"screenSize"`
}

type RefreshInput struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type BlockedPhone struct {
	Id           int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime time.Time    `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime   sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	Number       string       `gorm:"column:Number;type:bpchar(10);"`
}

func (BlockedPhone) TableName() string {
	return BlockedPhones
}

type Client struct {
	Id                       int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime             time.Time    `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime               sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	Issuer                   string       `gorm:"column:Issuer"`
	Audience                 string       `gorm:"column:Audience"`
	ValidateAudience         bool         `gorm:"column:ValidateAudience"`
	ValidateIssuer           bool         `gorm:"column:ValidateIssuer"`
	ValidateIssuerSigningKey bool         `gorm:"column:ValidateIssuerSigningKey"`
	ValidateLifetime         bool         `gorm:"column:ValidateLifetime"`
	CanRegister              bool         `gorm:"column:CanRegister"`
	CanLogin                 bool         `gorm:"column:CanLogin"`
	Alg                      string       `gorm:"column:Alg"`
	Enc                      string       `gorm:"column:Enc"`
	AccessTokenLifeTime      string       `gorm:"column:AccessTokenLifeTime;type:interval"`
	RefreshTokenLifeTime     string       `gorm:"column:RefreshTokenLifeTime;type:interval"`
	SupportCompression       bool         `gorm:"column:SupportCompression"`
	SigningKey               string       `gorm:"column:SigningKey"`
	EncryptingKey            string       `gorm:"column:EncryptingKey"`
	RequiredRoles            string       `gorm:"column:RequiredRoles"`
	DefaultRoles             string       `gorm:"column:DefaultRoles"`
}

func (Client) TableName() string {
	return Clients
}

type OtpAttempt struct {
	Id                  int64         `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTimeUtc     time.Time     `gorm:"column:CreationTimeUtc;not null"`
	ModificationTimeUtc sql.NullTime  `gorm:"column:ModificationTimeUtc"`
	UserId              sql.NullInt64 `gorm:"column:UserId"`
	User                *User         `gorm:"foreignKey:UserId"`
	Phone               string        `gorm:"column:Phone"`
	ClientId            int64         `gorm:"column:ClientId"`
	Client              Client        `gorm:"foreignKey:ClientId"`
	Salt                string        `gorm:"column:Salt"`
	IssueTime           time.Time     `gorm:"column:IssueTime;type:timestamp"`
	ExpireTime          time.Time     `gorm:"column:ExpireTime;type:timestamp"`
	UserIp              string        `gorm:"column:UserIp"`
	UserAgent           string        `gorm:"column:UserAgent"`
	OtpKind             Kind          `gorm:"column:Kind"`
}

func (OtpAttempt) TableName() string {
	return OtpAttempts
}

type Kind byte

const (
	Register Kind = 2
	Login    Kind = 4
)

var (
	Kind_name = map[byte]string{
		2: "Register",
		4: "Login",
	}
	Kind_value = map[string]byte{
		"Register": 2,
		"Login":    4,
	}
)

func (k Kind) Enum() *Kind {
	P := new(Kind)
	*P = k
	return P
}

var OtpKinds = []string{"Register", "Login"}

func (k Kind) String() string {
	switch k {
	case 2:
		return OtpKinds[0]
	case 4:
		return OtpKinds[1]
	default:
		return ""
	}
}

//func (TokenClaim) TableName() string {
//	return "TokenClaims"
//}

func GetJson(a *TokenClaim) (payload []byte) {
	payload, _ = json.Marshal(a)
	return
}

func (x *TokenClaim) GetAllRoles() []string {
	s := make([]string, len(x.Roles))
	for i, v := range x.Roles {
		s[i] = fmt.Sprintf("%v", v)
	}
	return s
}

type UserRole struct {
	UserId int64 `gorm:"primaryKey;autoIncrement:false;column:UserId;"`
	RoleId int64 `gorm:"primaryKey;autoIncrement:false;column:RoleId;"`
}

func (UserRole) TableName() string {
	return UserRoles
}

type Role struct {
	Id           sql.NullInt64 `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime time.Time     `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime   sql.NullTime  `gorm:"column:ModifyTime;type:timestamp"`
	Name         string        `gorm:"column:Name;" json:"name"`
	Title        string        `gorm:"column:Title;" json:"title"`
	IsInHouse    bool          `gorm:"column:IsInHouse;" json:"isInHouse"`
	Visible      bool          `gorm:"column:Visible;" json:"visible"`
	UserRoles    []UserRole
}

func (Role) TableName() string {
	return Roles
}

type User struct {
	Id            int64          `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime  time.Time      `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime    sql.NullTime   `gorm:"column:ModifyTime;type:timestamp"`
	PhoneNumber   string         `gorm:"uniqueIndex;column:PhoneNumber;type:bpchar(10);" json:"phoneNumber"`
	UserProfileId int64          `gorm:"column:UserProfileId" json:"userProfileId"`
	LastLoginTime time.Time      `gorm:"column:LastLoginTime;type:timestamp" json:"lastLoginTime"`
	UserRoles     []UserRole     //`gorm:"many2many:UserRoles;"`
	RefreshTokens []RefreshToken //`gorm:"many2many:RefreshTokens" json:"refreshTokens"`
	OtpAttempts   []*OtpAttempt  //`gorm:"many2many:OtpAttempts" json:"otpAttempts"`
}

func (User) TableName() string {
	return Users
}

type RefreshToken struct {
	Id           int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime time.Time    `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime   sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	UserId       int64        `gorm:"column:UserId" json:"userId"`
	User         User         `gorm:"foreignKey:UserId"`
	ClientId     int64        `gorm:"column:ClientId" json:"clientId"`
	Client       Client       `gorm:"foreignKey:ClientId"`
	Token        string       `gorm:"column:Token" json:"token"`
	IssueTime    time.Time    `gorm:"column:IssueTime;type:timestamp" json:"issueTime"`
	ExpireTime   time.Time    `gorm:"column:ExpireTime;type:timestamp" json:"expireTime"`
	AccessTokens []AccessToken
	IsRevoked    bool         `gorm:"column:IsRevoked" json:"isRevoked"`
	RevokeTime   sql.NullTime `gorm:"column:RevokeTime;type:timestamp" json:"revokeTime"`
}

func (RefreshToken) TableName() string {
	return RefreshTokens
}

type AccessToken struct {
	Id             int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime   time.Time    `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime     sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	RefreshTokenId int64        `gorm:"column:RefreshTokenId" json:"refreshTokenId"`
	RefreshToken   RefreshToken `gorm:"foreignKey:RefreshTokenId"`
	Token          string       `gorm:"column:Token" json:"token"`
	IssueTime      time.Time    `gorm:"column:IssueTime;type:timestamp" json:"issueTime"`
	ExpireTime     time.Time    `gorm:"column:ExpireTime;type:timestamp" json:"expireTime"`
	IsRevoked      bool         `gorm:"column:IsRevoked" json:"isRevoked"`
	RevokeTime     sql.NullTime `gorm:"column:RevokeTime;type:timestamp" json:"revokeTime"`
}

func (AccessToken) TableName() string {
	return AccessTokens
}

type UserProfile struct {
	Id                 int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	CreationTime       time.Time    `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime         sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	UserId             int64        `gorm:"column:UserId"`
	User               User         `gorm:"foreignKey:UserId"`
	FirstName          string       `gorm:"column:FirstName"`
	LastName           string       `gorm:"column:LastName"`
	Gender             Gender       `gorm:"column:Gender"`
	BirthDate          sql.NullTime `gorm:"column:BirthDate;type:timestamp"`
	JobTitle           string       `gorm:"column:JobTitle"`
	Email              string       `gorm:"column:Email"`
	ProfileImageFileId int64        `gorm:"column:ProfileImageFileId"`
	InviteCode         string       `gorm:"column:InviteCode"`
	Address            string       `gorm:"column:Address"`
	PostalCode         string       `gorm:"column:PostalCode"`
	Latitude           float64      `gorm:"column:Latitude"`
	Longitude          float64      `gorm:"column:Longitude"`
}

func (UserProfile) TableName() string {
	return UserProfiles
}

type Gender byte

var genderKinds = []string{"Male", "Female"}

func (g Gender) String() string {
	switch g {
	case 1:
		return genderKinds[0]
	case 2:
		return genderKinds[1]
	default:
		return ""
	}
}

type GiftCode struct {
	Id           int64         `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	Voucher      string        `gorm:"column:Voucher"`
	Description  string        `gorm:"column:Description"`
	IsUsed       bool          `gorm:"column:IsUsed"`
	UserIdUsed   sql.NullInt64 `gorm:"column:UserIdUsed"`
	RequestDate  time.Time     `gorm:"column:RequestDate;type:timestamp"`
	CreationTime time.Time     `gorm:"column:CreationTime;type:timestamp"`
	ModifyTime   sql.NullTime  `gorm:"column:ModifyTime;type:timestamp"`
}

func (GiftCode) TableName() string {
	return GiftCodes
}

// TrimDomain Trim Domain trims the domain prefix and query params if exists and implemented for Authorizer.pb.go
func (x *Request) TrimDomain() {
	x.URL = strings.TrimPrefix(x.URL, Domain)
	x.URL = strings.Split(x.URL, "?")[0]
}

func (x *TokenClaim) IsLifeTimeValid() bool {
	nbf, err := strconv.ParseInt(x.GetNotBefore(), 10, 64)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	exp, err := strconv.ParseInt(x.GetExpires(), 10, 64)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	now := time.Now().UTC().Unix()
	if nbf > now || exp < now {
		return false
	}
	return true
}
