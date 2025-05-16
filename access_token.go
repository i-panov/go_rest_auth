package main

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AccessTokenHeader struct {
	Algorithm string `json:"alg"`
	Type string `json:"type"`
}

type AccessTokenPayload struct {
	UserId string `json:"iss"`
	ExpirationTime int64 `json:"exp"`
}

type AccessToken struct {
	Header AccessTokenHeader
	Payload AccessTokenPayload
}

func (token *AccessToken) GetUnsignedToken() []byte {
	headerBytes, _ := json.Marshal(token.Header)
	headerEncodedBytes := EncodeBase64Url(headerBytes)

	payloadBytes, _ := json.Marshal(token.Payload)
	payloadEncodedBytes := EncodeBase64Url(payloadBytes)

	return ConcatBytes(headerEncodedBytes, payloadEncodedBytes, '.')
}

func (token *AccessToken) GetSignedToken(secretKey string) []byte {
	unsignedToken := token.GetUnsignedToken()
	signature := SignAccessToken(unsignedToken, secretKey)
	return ConcatBytes(unsignedToken, signature, '.')
}

func (token *AccessToken) GetSignedTokenString(secretKey string) string {
	return string(token.GetSignedToken(secretKey))
}

func SignAccessToken(unsignedToken []byte, secretKey string) []byte {
	secretKeyBytes := []byte(secretKey)
	signatureBytes := sha512.Sum512(append(unsignedToken, secretKeyBytes...))
	return EncodeBase64Url(signatureBytes[:])
}

func ParseAccessToken(value string) (*AccessToken, string, error) {
	parts := strings.Split(value, ".")

	if len(parts) != 3 {
		msg := fmt.Sprintf("The token has the wrong number of parts: %d", len(parts))
		return nil, "", errors.New(msg)
	}

	var token AccessToken

	decodedHeaderBytes, err := DecodeBase64Url([]byte(parts[0]))

	if err != nil {
		return nil, "", err
	}

	err = json.Unmarshal(decodedHeaderBytes, &token.Header)

	if err != nil {
		return nil, "", err
	}

	decodedPayloadBytes, err := DecodeBase64Url([]byte(parts[1]))

	if err != nil {
		return nil, "", err
	}

	err = json.Unmarshal(decodedPayloadBytes, &token.Payload)

	if err != nil {
		return nil, "", err
	}

	return &token, parts[2], nil
}

func CreateAccessToken(userId string, duration time.Duration) AccessToken {
	expirationTime := time.Now().Add(duration)

	return AccessToken{
		Header:  AccessTokenHeader{Type: "JWT", Algorithm: "sha512"},
		Payload: AccessTokenPayload{UserId: userId, ExpirationTime: expirationTime.Unix()},
	}
}
