package main

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
)

func SplitString(value string, separator rune) []string {
	return strings.FieldsFunc(value, func(c rune) bool {
		return c == separator
	})
}

func EncodeBase64Url(data []byte) []byte {
	resultLength := base64.URLEncoding.EncodedLen(len(data))
	result := make([]byte, resultLength)
	base64.URLEncoding.Encode(result, data)
	return result
}

func DecodeBase64Url(data []byte) ([]byte, error) {
	resultLength := base64.URLEncoding.DecodedLen(len(data))
	result := make([]byte, resultLength)
	_, err := base64.URLEncoding.Decode(result, data)

	if err != nil {
		return nil, err
	}

	result = bytes.TrimRight(result, "\x00")
	return result, nil
}

func ConcatBytes(left []byte, right []byte, separator byte) []byte {
	return append(append(left, separator), right...)
}

func GenerateRandomString(size uint) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	result := make([]rune, size)

	for index := range result {
		result[index] = letters[rand.Intn(len(letters))]
	}

	return string(result)
}
