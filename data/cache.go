package data

import (
	_ "bufio"
	_ "encoding/json"
	"log"
	_ "os"
	_ "strings"
	"time"

	"github.com/erfandiakoo/wedding/model"

	"github.com/dgraph-io/ristretto"
)

var (
	//Cache In memory cache
	Cache       *ristretto.Cache
	Error       error
	ok          bool
	ClientTable = "Clients"
)

func init() {
	Cache, Error = ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e8,
		MaxCost:     1 << 30,
		BufferItems: 1000,
	})
	if Error != nil {
		log.Fatalln(err)
	}
	//SetEntities()
}

func SetClientTable(Table []model.Client) (ok bool) {
	ok = Cache.SetWithTTL(ClientTable, Table, 0, 24*time.Hour)
	Cache.Wait()
	if !ok {
		log.Panicln("error of SetClientTable to Cache")
	}
	return
}

func GetClientsTable() (Table []model.Client, ok bool) {

	var table interface{}
	table, ok = Cache.Get(ClientTable)
	if !ok {
		ok = SetClientTable(getClientsTable())
		GetClientsTable()
	}
	log.Println("Client Table:", table)
	Table = table.([]model.Client)
	return
}

func CanRegister(TcClient string) (bool, int64) {
	table := FindClient(TcClient)
	if TcClient != table.Issuer {
		return false, 0
	}
	return table.CanRegister, table.Id
}

func CanLogin(TcClient string) (ClientTable model.Client, ok bool) {
	ClientTable = FindClient(TcClient)
	if ClientTable.Id == 0 {
		return ClientTable, false
	}
	return ClientTable, ClientTable.CanLogin
}

func GetRoles(Url string) (Roles []string, err error) {
	data, found := Cache.Get(Url)
	if !found {
		return nil, err
	}
	return data.([]string), nil
}
