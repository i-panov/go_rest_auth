package main

import (
	"log"
	"net/http"
	"time"

	"gopkg.in/mgo.v2"
)

const (
	SecretKey            = "SECRET_KEY"
	AccessTokenDuration  = time.Minute * 10
	RefreshTokenDuration = time.Hour * 24 * 30
)

func main() {
	session, err := mgo.Dial("mongodb://127.0.0.1")

	if err != nil {
		panic(err)
	}

	defer session.Close()
	
	usersRepository := &UsersRepository{
		UsersCollection: session.DB("usersdb").C("users"),
	}

	controller := &AppController{
		UsersRepository: usersRepository,
	}

	// чтобы было на чем тестировать удалим все старые записи и добавим одну новую

	_, err = usersRepository.Clear()

	if err != nil {
		panic(err)
	}

	err = usersRepository.Insert(&User{})

	if err != nil {
		panic(err)
	}

	http.HandleFunc("/get_users", controller.GetUsersAction)
	http.HandleFunc("/get_tokens", controller.GetTokensAction)
	http.HandleFunc("/ping", controller.PingAction)
	http.HandleFunc("/refresh_tokens", controller.RefreshTokensAction)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
