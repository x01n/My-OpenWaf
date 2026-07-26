package memreclaim

import (
	"testing"
	"time"
)

func TestStartStop(t *testing.T) {
	stop := Start(Config{
		Interval:        20 * time.Millisecond,
		IdleRounds:      1,
		MinHeapReleased: 1, // 任意小值，便于触发或跳过
	})
	time.Sleep(50 * time.Millisecond)
	stop()
	// 二次 stop 不应 panic
	stop()
}
