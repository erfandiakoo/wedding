package data

import (
	"time"

	"github.com/erfandiakoo/wedding/publicFunction"

	"github.com/erfandiakoo/wedding/model"
)

func IsUserRegistered(userId int64) (ok bool) {
	var c int64
	db.Model(model.UserReserve{}).Where(`"UserId" = ? `, userId).Count(&c)
	if c > 0 {
		return false
	}
	db.Model(model.UserReserve{}).Create(&model.UserReserve{
		Id:              publicFunction.IdGenerator.Generate().Int64(),
		UserId:          userId,
		CreationTimeUtc: time.Now().UTC(),
	})
	return true
}
