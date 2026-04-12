package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// RedisOptions avoids importing package core (same fields as [core.Config] Redis slice).
type RedisOptions struct {
	Addr     string
	Password string
	DB       int
}

// OptionalClient returns a Redis client or nil when not configured.
func OptionalClient(opt RedisOptions) *goredis.Client {
	if opt.Addr == "" {
		return nil
	}
	return goredis.NewClient(&goredis.Options{
		Addr:         opt.Addr,
		Password:     opt.Password,
		DB:           opt.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
}

// Ping checks connectivity when client is non-nil.
func Ping(ctx context.Context, c *goredis.Client) error {
	if c == nil {
		return nil
	}
	return c.Ping(ctx).Err()
}
