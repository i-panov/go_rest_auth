package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func GenerateRefreshToken(accessToken string, expirationTime time.Time) string {
	randomPart := GenerateRandomString(8)
	tokenPart := accessToken[len(accessToken)-6:]
	timePart := fmt.Sprint(expirationTime.Unix())
	encodedTokenBytes := EncodeBase64Url([]byte(randomPart + "." + tokenPart + "." + timePart))
	return string(encodedTokenBytes)
}

func GetRefreshTokenExpirationTime(value string) (*time.Time, error) {
	decodedTokenBytes, err := DecodeBase64Url([]byte(value))

	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(decodedTokenBytes), ".")

	if len(parts) != 3 {
		msg := fmt.Sprintf("The token has the wrong number of parts: %d", len(parts))
		return nil, errors.New(msg)
	}

	expirationTimeSeconds, err := strconv.ParseInt(parts[2], 10, 64)

	if err != nil {
		return nil, err
	}

	expirationTime := time.Unix(expirationTimeSeconds, 0)
	return &expirationTime, nil
}
