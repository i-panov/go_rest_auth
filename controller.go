package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AppController struct {
	UsersRepository *UsersRepository
}

func WriteResponseJson(writer http.ResponseWriter, object any) {
	data, _ := json.Marshal(object)
	fmt.Fprint(writer, string(data))
}

func WriteResponseError(writer http.ResponseWriter, err error) {
	writer.WriteHeader(http.StatusBadRequest)
	WriteResponseJson(writer, map[string]string{"error": err.Error()})
}

func (c *AppController) ValidateAccessToken(request *http.Request) (*AccessToken, error) {
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

	_, err = c.UsersRepository.Find(accessToken.Payload.UserId)

	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

//---------------------------------------------------------------------------

// Для удобства action получения пользователей без авторизации. Я понимаю конечно что токены не должны "смотреть" наружу. Это не релизная версия =)
func (c *AppController) GetUsersAction(writer http.ResponseWriter, request *http.Request) {
	users, err := c.UsersRepository.FindAll()

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	WriteResponseJson(writer, users)
}

func (c *AppController) GetTokensAction(writer http.ResponseWriter, request *http.Request) {
	userId := request.URL.Query().Get("user_id")

	if userId == "" {
		WriteResponseError(writer, errors.New("User id could not be blank"))
		return
	}

	// Проверим что юзер существует. Сами его данные не нужны. Аналогов SQL-вому EXISTS не нашел.

	_, err := c.UsersRepository.Find(userId)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	accessToken := CreateAccessToken(userId, AccessTokenDuration)
	accessTokenString := accessToken.GetSignedTokenString(SecretKey)
	refreshToken := GenerateRefreshToken(accessTokenString, time.Now().Add(RefreshTokenDuration))
	refreshTokenHashBytes, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	refreshTokenHash := string(refreshTokenHashBytes)
	err = c.UsersRepository.UpdateRefreshToken(userId, refreshTokenHash)

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
func (c *AppController) PingAction(writer http.ResponseWriter, request *http.Request) {
	_, err := c.ValidateAccessToken(request)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	fmt.Fprint(writer, "pong")
}

func (c *AppController) RefreshTokensAction(writer http.ResponseWriter, request *http.Request) {
	accessToken, err := c.ValidateAccessToken(request)

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

	user, err := c.UsersRepository.Find(accessToken.Payload.UserId)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(refreshToken))

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	newAccessToken := CreateAccessToken(accessToken.Payload.UserId, AccessTokenDuration)
	newRefreshToken := GenerateRefreshToken(newAccessToken.GetSignedTokenString(SecretKey), time.Now().Add(RefreshTokenDuration))

	newRefreshTokenHashBytes, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	newRefreshTokenHash := string(newRefreshTokenHashBytes)
	err = c.UsersRepository.UpdateRefreshToken(accessToken.Payload.UserId, newRefreshTokenHash)

	if err != nil {
		WriteResponseError(writer, err)
		return
	}

	WriteResponseJson(writer, map[string]string{
		"access_token":  newAccessToken.GetSignedTokenString(SecretKey),
		"refresh_token": newRefreshToken,
	})
}
