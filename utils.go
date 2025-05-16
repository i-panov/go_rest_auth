package main

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"sync"
	"time"
)

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

var (
	randomLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMu sync.Mutex
)

func GenerateRandomString(size int) string {
	if size <= 0 {
		return ""
	}

	rngMu.Lock()
	defer rngMu.Unlock()

	result := strings.Builder{}
	result.Grow(size)
	lettersLen := len(randomLetters)

	for range size {
		result.WriteRune(randomLetters[rng.Intn(lettersLen)])
	}

	return result.String()
}
