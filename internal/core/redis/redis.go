package redis

import (
	"context"
	"net"
	"time"

	rueidis "github.com/redis/rueidis"
)

// RedisOptions avoids importing package core (same fields as [core.Config] Redis slice).
type RedisOptions struct {
	Addr     string
	Password string
	DB       int
}

func OptionalClient(opt RedisOptions) rueidis.Client {
	if opt.Addr == "" {
		return nil
	}
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:      []string{opt.Addr},
		Password:         opt.Password,
		SelectDB:         opt.DB,
		Dialer:           net.Dialer{Timeout: 5 * time.Second},
		ConnWriteTimeout: 3 * time.Second,
		DisableCache:     true,
	})
	if err != nil {
		return nil
	}
	return client
}

// Ping checks connectivity when client is non-nil.
func Ping(ctx context.Context, c rueidis.Client) error {
	if c == nil {
		return nil
	}
	return c.Do(ctx, c.B().Ping().Build()).Error()
}
