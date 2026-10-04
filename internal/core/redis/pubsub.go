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

	rueidis "github.com/redis/rueidis"
)

const configSyncChannel = "openwaf:config:reload"
const configSyncActionReload = "reload"

type configSyncMessage struct {
	SourceID string `json:"source_id"`
	Action   string `json:"action"`
}

/**
 * ConfigSync 通过 Redis 发布/订阅配置重载事件。
 *
 * 多个 WAF 节点借助它在管理端 API 变更后保持同步。
 */
type ConfigSync struct {
	client    rueidis.Client
	log       *slog.Logger
	sourceID  string
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewConfigSync 创建配置同步处理器。client 为 nil 时返回 nil。
func NewConfigSync(client rueidis.Client, log *slog.Logger, sourceID string) *ConfigSync {
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

// PublishReload 通知所有节点配置已变更。
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
	if err := cs.client.Do(ctx, cs.client.B().Publish().Channel(configSyncChannel).Message(string(payload)).Build()).Error(); err != nil {
		cs.log.Warn("config sync publish failed", slog.Any("err", err))
	}
}

// Subscribe 监听重载事件并调用 reload 函数。
// 在 Close() 被调用前一直阻塞。
func (cs *ConfigSync) Subscribe(reload func() error) {
	if cs == nil || cs.client == nil {
		return
	}

	subCmd := cs.client.B().Subscribe().Channel(configSyncChannel).Build()

	go func() {
		<-cs.stopCh
		cs.client.Close()
	}()
	_ = cs.client.Receive(context.Background(), subCmd, func(msg rueidis.PubSubMessage) {
		if msg.Message == configSyncActionReload {
			cs.log.Info("received config sync reload")
			if err := reload(); err != nil {
				cs.log.Error("config sync reload failed", slog.Any("err", err))
			}
			return
		}

		var event configSyncMessage
		if err := json.Unmarshal([]byte(msg.Message), &event); err != nil {
			cs.log.Warn("config sync payload decode failed", slog.Any("err", err))
			return
		}
		if event.Action != configSyncActionReload {
			return
		}
		if event.SourceID != "" && event.SourceID == cs.sourceID {
			return
		}
		cs.log.Info("received config sync reload")
		if err := reload(); err != nil {
			cs.log.Error("config sync reload failed", slog.Any("err", err))
		}
	})
}

// Close 停止订阅者。
func (cs *ConfigSync) Close() {
	if cs == nil {
		return
	}
	cs.closeOnce.Do(func() {
		close(cs.stopCh)
	})
}
