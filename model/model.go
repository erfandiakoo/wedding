package model

import (
	"database/sql"
	"time"
)

type UserReserve struct {
	Id              int64        `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	UserId          int64        `gorm:"column:UserId" json:"userId"`
	User            User         `gorm:"foreignKey:UserId"`
	CreationTimeUtc time.Time    `gorm:"column:CreationTimeUtc;not null"`
	ModifyTime      sql.NullTime `gorm:"column:ModifyTime;type:timestamp"`
	FullName        string       `gorm:"column:FullName"`
	Service         string       `gorm:"column:Service"`
	Comments        string       `gorm:"column:Comments"`
}

type Services struct {
	Id     int64  `gorm:"UNIQUEINDEX;AUTO_INCREMENT:false;PRIMARY_KEY;column:Id;not null;type:int8"`
	Title  string `gorm:"column:Title"`
	IsIdle bool   `gorm:"column:IsIdle"`
}

func (UserReserve) TableName() string {
	return "UserReserves"
}

func (Services) TableName() string {
	return "Services"
}

type GetReserveListResponse struct {
	RowNumber int64  `json:"rowNumber,string"`
	Id        int64  `json:"id,string"`
	FullName  string `json:"fullName"`
	Service   string `json:"service"`
	Phone     string `json:"phone"`
}

type ReserveRequest struct {
	FullName string `json:"fullName"`
	Service  string `json:"service"`
	Comments string `json:"comments"`
}

type ServiceResponse struct {
	Id    int64  `json:"id,string"`
	Title string `json:"title"`
}

type ServiceInput struct {
	Title string `json:"title"`
}

type ResponseModel struct {
	Data    map[string]interface{} `json:"data,omitempty"`
	Message string                 `json:"msg,omitempty"`
	Code    int                    `json:"code"`
}

type ResponseModel2 struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"msg,omitempty"`
	Code    int         `json:"code"`
}
