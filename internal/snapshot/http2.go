package snapshot

import "encoding/json"

const (
	MinHTTP2ReadFrameSize             uint32 = 16 << 10
	MaxHTTP2ReadFrameSize             uint32 = (1 << 24) - 1
	MinHTTP2UploadBufferPerConnection int32  = 65535
	MaxHTTP2UploadBufferPerConnection int32  = 1 << 20
	MaxHTTP2UploadBufferPerStream     int32  = 1 << 20
	MaxHTTP2ConcurrentStreams         uint32 = 1000
	MaxHTTP2HeaderBytes               int    = 1 << 20
	MaxHTTP2HeaderFields              int    = 100
	MaxHTTP2Handlers                  int    = 1000
	MaxHTTP2QueuedControlFrames       int    = 10000
)

type HTTP2Config struct {
	ReadTimeoutSeconds           int    `json:"read_timeout_seconds"`
	DisableKeepalive             bool   `json:"disable_keepalive"`
	PermitProhibitedCipherSuites bool   `json:"permit_prohibited_cipher_suites"`
	MaxConcurrentStreams         uint32 `json:"max_concurrent_streams"`
	MaxReadFrameSize             uint32 `json:"max_read_frame_size"`
	IdleTimeoutSeconds           int    `json:"idle_timeout_seconds"`
	MaxUploadBufferPerConnection int32  `json:"max_upload_buffer_per_connection"`
	MaxUploadBufferPerStream     int32  `json:"max_upload_buffer_per_stream"`
	MaxHeaderBytes               int    `json:"max_header_bytes"`
	MaxHeaderFields              int    `json:"max_header_fields"`
	MaxHandlers                  int    `json:"max_handlers"`
	MaxQueuedControlFrames       int    `json:"max_queued_control_frames"`
}

func DefaultHTTP2Config() HTTP2Config {
	return HTTP2Config{
		ReadTimeoutSeconds:           60,
		DisableKeepalive:             false,
		PermitProhibitedCipherSuites: true,
		MaxConcurrentStreams:         100,
		MaxReadFrameSize:             64 << 10,
		IdleTimeoutSeconds:           10,
		MaxUploadBufferPerConnection: 512 << 10,
		MaxUploadBufferPerStream:     256 << 10,
		MaxHeaderBytes:               1 << 20,
		MaxHeaderFields:              100,
		MaxHandlers:                  0,
		MaxQueuedControlFrames:       10000,
	}
}

func NormalizeHTTP2Config(cfg HTTP2Config) HTTP2Config {
	defaults := DefaultHTTP2Config()
	if cfg.ReadTimeoutSeconds <= 0 {
		cfg.ReadTimeoutSeconds = defaults.ReadTimeoutSeconds
	}
	if cfg.MaxConcurrentStreams == 0 {
		cfg.MaxConcurrentStreams = defaults.MaxConcurrentStreams
	} else if cfg.MaxConcurrentStreams > MaxHTTP2ConcurrentStreams {
		cfg.MaxConcurrentStreams = MaxHTTP2ConcurrentStreams
	}
	if cfg.MaxReadFrameSize < MinHTTP2ReadFrameSize {
		cfg.MaxReadFrameSize = defaults.MaxReadFrameSize
	} else if cfg.MaxReadFrameSize > MaxHTTP2ReadFrameSize {
		cfg.MaxReadFrameSize = MaxHTTP2ReadFrameSize
	}
	if cfg.IdleTimeoutSeconds <= 0 {
		cfg.IdleTimeoutSeconds = defaults.IdleTimeoutSeconds
	}
	if cfg.MaxUploadBufferPerConnection < MinHTTP2UploadBufferPerConnection {
		cfg.MaxUploadBufferPerConnection = defaults.MaxUploadBufferPerConnection
	} else if cfg.MaxUploadBufferPerConnection > MaxHTTP2UploadBufferPerConnection {
		cfg.MaxUploadBufferPerConnection = MaxHTTP2UploadBufferPerConnection
	}
	if cfg.MaxUploadBufferPerStream <= 0 {
		cfg.MaxUploadBufferPerStream = defaults.MaxUploadBufferPerStream
	} else if cfg.MaxUploadBufferPerStream > MaxHTTP2UploadBufferPerStream {
		cfg.MaxUploadBufferPerStream = MaxHTTP2UploadBufferPerStream
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = defaults.MaxHeaderBytes
	} else if cfg.MaxHeaderBytes > MaxHTTP2HeaderBytes {
		cfg.MaxHeaderBytes = MaxHTTP2HeaderBytes
	}
	if cfg.MaxHeaderFields <= 0 {
		cfg.MaxHeaderFields = defaults.MaxHeaderFields
	} else if cfg.MaxHeaderFields > MaxHTTP2HeaderFields {
		cfg.MaxHeaderFields = MaxHTTP2HeaderFields
	}
	if cfg.MaxHandlers < 0 {
		cfg.MaxHandlers = defaults.MaxHandlers
	} else if cfg.MaxHandlers > MaxHTTP2Handlers {
		cfg.MaxHandlers = MaxHTTP2Handlers
	}
	if cfg.MaxQueuedControlFrames <= 0 {
		cfg.MaxQueuedControlFrames = defaults.MaxQueuedControlFrames
	} else if cfg.MaxQueuedControlFrames > MaxHTTP2QueuedControlFrames {
		cfg.MaxQueuedControlFrames = MaxHTTP2QueuedControlFrames
	}
	return cfg
}

func LoadHTTP2Config(raw string) HTTP2Config {
	cfg := DefaultHTTP2Config()
	if raw == "" {
		return cfg
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultHTTP2Config()
	}
	return NormalizeHTTP2Config(cfg)
}
