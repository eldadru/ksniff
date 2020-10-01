package utils

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestRunWhileFalse_Instant(t *testing.T) {
	// given
	f := func() bool {
		return true
	}

	// when
	result := RunWhileFalse(f, time.Minute, time.Minute)

	// then
	assert.True(t, result)
}

func TestRunWhileFalse_1SecTimeoutFalse(t *testing.T) {
	// given
	f := func() bool {
		return false
	}

	// when
	begin := time.Now()
	result := RunWhileFalse(f, time.Second, time.Second)
	end := time.Now()
	diff := end.Sub(begin)

	// then
	assert.False(t, result)
	assert.True(t, (diff.Seconds() > 0 && diff.Seconds() < 2))
}

func TestRunWhileFalse_NoTimeout(t *testing.T) {
	// given
	f := func() bool {
		return false
	}
	// This part is tricky since we don't want our test case to run forever.
	// Adding a timeout outside scope of RunWhileFalse
	ctx, cancel := context.WithTimeout(context.Background(), 1 * time.Second)
	defer cancel()

	// when
	go func() {
		RunWhileFalse(f, 0*time.Second, time.Second)
		cancel()
	}()

	// then
	<- ctx.Done()
	assert.Equal(t, context.DeadlineExceeded, ctx.Err())
}

func TestRuneWhileFalse_1SecTimeoutTrue(t *testing.T) {
	// given
	ret := false
	f := func() bool {
		return ret
	}
	time.AfterFunc(1 * time.Second, func() { ret = true })

	// when
	result := RunWhileFalse(f, 5*time.Second, time.Second)

	// then
	assert.True(t, result)
}