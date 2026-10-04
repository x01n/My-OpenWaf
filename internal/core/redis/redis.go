package redis

import (
	"context"
	"net"
	"time"

	rueidis "github.com/redis/rueidis"
)

// RedisOptions 避免导入 core 包（字段与 [core.Config] 的 Redis 部分一致）。
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

// Ping 在 client 非 nil 时检查连通性。
func Ping(ctx context.Context, c rueidis.Client) error {
	if c == nil {
		return nil
	}
	return c.Do(ctx, c.B().Ping().Build()).Error()
}
