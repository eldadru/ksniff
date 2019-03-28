package utils

import (
	"math/rand"
	"time"
)

func RunWhileFalse(fn func() bool, timeout time.Duration, delay time.Duration) bool {
	if fn() {
		return true
	}

	delayTick := time.NewTicker(delay)
	timeoutTick := time.NewTimer(timeout)

	defer delayTick.Stop()
	defer timeoutTick.Stop()

	for {
		select {
		case <-timeoutTick.C:
			return false
		case <-delayTick.C:
			if fn() {
				return true
			}
		}
	}
}

func GenerateRandomString(length int) string {

	rand.Seed(time.Now().UnixNano())

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}
