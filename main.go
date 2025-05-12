package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type User struct {
	Id           bson.ObjectId `bson:"_id,omitempty"`
	RefreshToken string        `bson:"refresh_token"`
}

const (
	SecretKey            = "SECRET_KEY"
	AccessTokenDuration  = time.Minute * 10
	RefreshTokenDuration = time.Hour * 24 * 30
)

// Не смог придумать другого способа прокинуть эту переменную кроме как сделать ее глобальной.
var usersCollection *mgo.Collection

func FindUser(userId string) (*User, error) {
	var user User
	err := usersCollection.FindId(bson.ObjectIdHex(userId)).One(&user)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func CreateAccessToken(userId string) AccessToken {
	expirationTime := time.Now().Add(AccessTokenDuration)

	return AccessToken{
		Header:  AccessTokenHeader{Type: "JWT", Algorithm: "sha512"},
		Payload: AccessTokenPayload{UserId: userId, ExpirationTime: expirationTime.Unix()},
	}
}

func WriteResponseJson(writer http.ResponseWriter, object interface{}) {
	data, _ := json.Marshal(object)
	fmt.Fprint(writer, string(data))
}

func WriteResponseError(writer http.ResponseWriter, err error) {
	writer.WriteHeader(http.StatusBadRequest)
	WriteResponseJson(writer, map[string]string{"error": err.Error()})
}

func ValidateAccessToken(request *http.Request) (*AccessToken, error) {
	accessTokenString := request.URL.Query().Get("access_token")

	if accessTokenString == "" {
		return nil, errors.New("access token could not be blank")
	}

	accessToken, _, err := ParseAccessToken(accessTokenString)

	if err != nil {
		return nil, err
	}

	if accessToken.GetSignedTokenString(SecretKey) != accessTokenString {
		return nil, errors.New("invalid access token")
	}

	_, err = FindUser(accessToken.Payload.UserId)

	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

//---------------------------------------------------------------------------

// Для удобства action получения пользователей без авторизации. Я понимаю конечно что токены не должны "смотреть" наружу. Это не релизная версия =)
func GetUsersAction(writer http.ResponseWriter, request *http.Request) {
	var users []User
	err := usersCollection.Find(bson.M{}).All(&users)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	WriteResponseJson(writer, users)
}

func GetTokensAction(writer http.ResponseWriter, request *http.Request) {
	userId := request.URL.Query().Get("user_id")

	if userId == "" {
		WriteResponseError(writer, errors.New("User id could not be blank"))
		return
	}

	// Проверим что юзер существует. Сами его данные не нужны. Аналогов SQL-вому EXISTS не нашел.

	_, err := FindUser(userId)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	accessToken := CreateAccessToken(userId)
	accessTokenString := accessToken.GetSignedTokenString(SecretKey)
	refreshToken := GenerateRefreshToken(accessTokenString, time.Now().Add(RefreshTokenDuration))
	refreshTokenHashBytes, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	refreshTokenHash := string(refreshTokenHashBytes)
	err = usersCollection.UpdateId(bson.ObjectIdHex(userId), bson.M{"refresh_token": refreshTokenHash})

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	WriteResponseJson(writer, map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": refreshToken,
	})
}

// Action, требующий авторизации. Для примера.
func PingAction(writer http.ResponseWriter, request *http.Request) {
	_, err := ValidateAccessToken(request)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	fmt.Fprint(writer, "pong")
}

func RefreshTokensAction(writer http.ResponseWriter, request *http.Request) {
	accessToken, err := ValidateAccessToken(request)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	refreshToken := request.URL.Query().Get("refresh_token")

	if refreshToken == "" {
		WriteResponseError(writer, errors.New("refresh token could not be blank"))
		return
	}

	refreshTokenExpirationTime, err := GetRefreshTokenExpirationTime(refreshToken)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	if refreshTokenExpirationTime.Before(time.Now()) {
		WriteResponseError(writer, errors.New("refresh token is expired"))
		return
	}

	user, err := FindUser(accessToken.Payload.UserId)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(refreshToken))

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	newAccessToken := CreateAccessToken(accessToken.Payload.UserId)
	newRefreshToken := GenerateRefreshToken(newAccessToken.GetSignedTokenString(SecretKey), time.Now().Add(RefreshTokenDuration))

	newRefreshTokenHashBytes, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	newRefreshTokenHash := string(newRefreshTokenHashBytes)
	err = usersCollection.UpdateId(bson.ObjectIdHex(accessToken.Payload.UserId), bson.M{"refresh_token": newRefreshTokenHash})

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	WriteResponseJson(writer, map[string]string{
		"access_token":  newAccessToken.GetSignedTokenString(SecretKey),
		"refresh_token": newRefreshToken,
	})
}

//---------------------------------------------------------------------------

func main() {
	session, err := mgo.Dial("mongodb://127.0.0.1")

	if err != nil {
		panic(err)
	}

	defer session.Close()
	usersCollection = session.DB("usersdb").C("users")

	// чтобы было на чем тестировать удалим все старые записи и добавим одну новую

	_, err = usersCollection.RemoveAll(bson.M{})

	if err != nil {
		panic(err)
	}

	err = usersCollection.Insert(&User{})

	if err != nil {
		panic(err)
	}

	http.HandleFunc("/get_users", GetUsersAction)
	http.HandleFunc("/get_tokens", GetTokensAction)
	http.HandleFunc("/ping", PingAction)
	http.HandleFunc("/refresh_tokens", RefreshTokensAction)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
