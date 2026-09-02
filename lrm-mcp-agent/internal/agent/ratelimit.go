package agent

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int
	burst    int
}

type visitor struct {
	tokens   int
	lastSeen time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		burst:    burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	v, ok := rl.visitors[ip]
	if !ok {
		rl.visitors[ip] = &visitor{tokens: rl.burst - 1, lastSeen: time.Now()}
		return true
	}
	elapsed := time.Since(v.lastSeen)
	v.tokens += int(elapsed.Seconds()) * rl.rate / 60
	if v.tokens > rl.burst {
		v.tokens = rl.burst
	}
	v.lastSeen = time.Now()
	if v.tokens <= 0 {
		return false
	}
	v.tokens--
	return true
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}
