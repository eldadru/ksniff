package utils

import "time"

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
