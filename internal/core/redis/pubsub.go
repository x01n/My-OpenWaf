package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const configSyncChannel = "openwaf:config:reload"
const configSyncActionReload = "reload"

type configSyncMessage struct {
	SourceID string `json:"source_id"`
	Action   string `json:"action"`
}

// ConfigSync publishes and subscribes to config-reload events via Redis pub/sub.
// Multiple WAF nodes use this to stay in sync after admin API mutations.
type ConfigSync struct {
	client    *goredis.Client
	log       *slog.Logger
	sourceID  string
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewConfigSync creates a config sync handler. Returns nil if client is nil.
func NewConfigSync(client *goredis.Client, log *slog.Logger, sourceID string) *ConfigSync {
	if client == nil {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	if sourceID == "" {
		sourceID = newConfigSyncSourceID()
	}
	return &ConfigSync{
		client:   client,
		log:      log,
		sourceID: sourceID,
		stopCh:   make(chan struct{}),
	}
}

func newConfigSyncSourceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("cfgsync-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// PublishReload notifies all nodes that config has changed.
func (cs *ConfigSync) PublishReload() {
	if cs == nil || cs.client == nil {
		return
	}
	payload, err := json.Marshal(configSyncMessage{
		SourceID: cs.sourceID,
		Action:   configSyncActionReload,
	})
	if err != nil {
		cs.log.Warn("config sync payload marshal failed", slog.Any("err", err))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cs.client.Publish(ctx, configSyncChannel, payload).Err(); err != nil {
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
		if msg.Payload == configSyncActionReload {
			cs.log.Info("received config sync reload")
			if err := reload(); err != nil {
				cs.log.Error("config sync reload failed", slog.Any("err", err))
			}
			continue
		}

		var event configSyncMessage
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			cs.log.Warn("config sync payload decode failed", slog.Any("err", err))
			continue
		}
		if event.Action != configSyncActionReload {
			continue
		}
		if event.SourceID != "" && event.SourceID == cs.sourceID {
			continue
		}
		cs.log.Info("received config sync reload")
		if err := reload(); err != nil {
			cs.log.Error("config sync reload failed", slog.Any("err", err))
		}
	}
}

// Close stops the subscriber.
func (cs *ConfigSync) Close() {
	if cs == nil {
		return
	}
	cs.closeOnce.Do(func() {
		close(cs.stopCh)
	})
}
