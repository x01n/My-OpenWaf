package redis

import (
	"context"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const configSyncChannel = "openwaf:config:reload"

// ConfigSync publishes and subscribes to config-reload events via Redis pub/sub.
// Multiple WAF nodes use this to stay in sync after admin API mutations.
type ConfigSync struct {
	client *goredis.Client
	log    *slog.Logger
	stopCh chan struct{}
}

// NewConfigSync creates a config sync handler. Returns nil if client is nil.
func NewConfigSync(client *goredis.Client, log *slog.Logger) *ConfigSync {
	if client == nil {
		return nil
	}
	return &ConfigSync{
		client: client,
		log:    log,
		stopCh: make(chan struct{}),
	}
}

// PublishReload notifies all nodes that config has changed.
func (cs *ConfigSync) PublishReload() {
	if cs == nil || cs.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cs.client.Publish(ctx, configSyncChannel, "reload").Err(); err != nil {
		cs.log.Warn("config sync publish failed", slog.Any("err", err))
	}
}

// Subscribe listens for reload events and calls the reload function.
// Blocks until Close() is called.
func (cs *ConfigSync) Subscribe(reload func() error) {
	if cs == nil || cs.client == nil {
		return
	}

	sub := cs.client.Subscribe(context.Background(), configSyncChannel)
	ch := sub.Channel()

	go func() {
		<-cs.stopCh
		_ = sub.Close()
	}()

	for msg := range ch {
		if msg.Payload == "reload" {
			cs.log.Info("received config sync reload")
			if err := reload(); err != nil {
				cs.log.Error("config sync reload failed", slog.Any("err", err))
			}
		}
	}
}

// Close stops the subscriber.
func (cs *ConfigSync) Close() {
	if cs == nil {
		return
	}
	close(cs.stopCh)
}
