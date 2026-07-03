package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"My-OpenWaf/internal/core/database"
	"My-OpenWaf/internal/store"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type mockRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	commands []string
}

func startMockRedisServer(t *testing.T) *mockRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock redis: %v", err)
	}

	srv := &mockRedisServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()
	return srv
}

func (s *mockRedisServer) Addr() string { return s.ln.Addr().String() }

func (s *mockRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *mockRedisServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *mockRedisServer) record(args []string) {
	parts := make([]string, len(args))
	for i := range args {
		parts[i] = strings.ToUpper(args[i])
	}

	s.mu.Lock()
	s.commands = append(s.commands, strings.Join(parts, " "))
	s.mu.Unlock()
}

func (s *mockRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		s.record(args)

		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = conn.Write([]byte("-ERR unknown command 'hello'\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func readRESPArgs(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array, got %q", line)
	}

	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}

		header = strings.TrimRight(header, "\r\n")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", header)
		}

		length, err := strconv.Atoi(header[1:])
		if err != nil {
			return nil, err
		}

		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if _, err := r.Discard(2); err != nil {
			return nil, err
		}

		args = append(args, string(buf))
	}

	return args, nil
}

func seedRedisConfigDB(t *testing.T, dbPath string, raw string) {
	t.Helper()

	db, err := database.Open(database.Options{
		Driver:  "sqlite",
		DSN:     dbPath,
		DataDir: filepath.Dir(dbPath),
	})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	defer closeRuntimeDB(db)

	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate system settings: %v", err)
	}
	if err := db.Create(&store.SystemSettings{
		Key:   store.SettingKeyRedisConfig,
		Value: raw,
	}).Error; err != nil {
		t.Fatalf("seed redis_config: %v", err)
	}
}

func seedRedisConfigDBAndOpen(t *testing.T, dbPath string, raw string) {
	t.Helper()
	seedRedisConfigDB(t, dbPath, raw)
}

func setRuntimeEnv(t *testing.T, dbPath string, logDBPath string) {
	t.Helper()

	t.Setenv("MY_OPENWAF_DB_DRIVER", "sqlite")
	t.Setenv("MY_OPENWAF_DSN", dbPath)
	t.Setenv("MY_OPENWAF_LOG_DSN", logDBPath)
	t.Setenv("MY_OPENWAF_DATA", filepath.Dir(dbPath))
	t.Setenv("MY_OPENWAF_ADMIN_BIND", ":9443")
}

func TestApplyStoredRedisConfigOverridesEnvValues(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "waf.db")
	seedRedisConfigDBAndOpen(t, dbPath, `{"enabled":true,"addr":"127.0.0.1:6380","password":"db-pass","db":5}`)

	db, err := database.Open(database.Options{
		Driver:  "sqlite",
		DSN:     dbPath,
		DataDir: filepath.Dir(dbPath),
	})
	if err != nil {
		t.Fatalf("reopen sqlite db: %v", err)
	}
	defer closeRuntimeDB(db)

	cfg := Config{
		RedisAddr:     "127.0.0.1:6379",
		RedisPassword: "env-pass",
		RedisDB:       1,
	}
	got := applyStoredRedisConfig(db, cfg)

	if got.RedisAddr != "127.0.0.1:6380" {
		t.Fatalf("redis addr = %q, want %q", got.RedisAddr, "127.0.0.1:6380")
	}
	if got.RedisPassword != "db-pass" {
		t.Fatalf("redis password = %q, want db-pass", got.RedisPassword)
	}
	if got.RedisDB != 5 {
		t.Fatalf("redis db = %d, want 5", got.RedisDB)
	}
}

func TestRuntimeStoredRedisConfigQueryUsesDialectQuotedKeyColumn(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=127.0.0.1 user=openwaf dbname=openwaf sslmode=disable",
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run postgres db: %v", err)
	}

	sql := db.Where(systemSettingKeyEquals(store.SettingKeyRedisConfig)).First(&store.SystemSettings{}).Statement.SQL.String()
	if strings.Contains(sql, "`key`") {
		t.Fatalf("SQL should not contain MySQL-style key quoting: %s", sql)
	}
	if !strings.Contains(sql, `"key"`) {
		t.Fatalf("SQL should contain dialect-quoted key column: %s", sql)
	}
}

func TestApplyStoredRedisConfigDisablesEnvRedisWhenStoredConfigDisabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "waf.db")
	seedRedisConfigDBAndOpen(t, dbPath, `{"enabled":false,"addr":"127.0.0.1:6380","password":"db-pass","db":5}`)

	db, err := database.Open(database.Options{
		Driver:  "sqlite",
		DSN:     dbPath,
		DataDir: filepath.Dir(dbPath),
	})
	if err != nil {
		t.Fatalf("reopen sqlite db: %v", err)
	}
	defer closeRuntimeDB(db)

	cfg := Config{
		RedisAddr:     "127.0.0.1:6379",
		RedisPassword: "env-pass",
		RedisDB:       1,
	}
	got := applyStoredRedisConfig(db, cfg)

	if got.RedisAddr != "" {
		t.Fatalf("redis addr = %q, want empty", got.RedisAddr)
	}
	if got.RedisPassword != "" {
		t.Fatalf("redis password = %q, want empty", got.RedisPassword)
	}
	if got.RedisDB != 0 {
		t.Fatalf("redis db = %d, want 0", got.RedisDB)
	}
}

func TestNewRuntimeUsesStoredRedisConfigOnStartup(t *testing.T) {
	srv := startMockRedisServer(t)
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "waf.db")
	logDBPath := filepath.Join(dir, "waf_logs.db")
	seedRedisConfigDBAndOpen(t, dbPath, fmt.Sprintf(`{"enabled":true,"addr":"%s","password":"secret-pass","db":7}`, srv.Addr()))

	setRuntimeEnv(t, dbPath, logDBPath)
	t.Setenv("MY_OPENWAF_REDIS_ADDR", "127.0.0.1:1")
	t.Setenv("MY_OPENWAF_REDIS_PASSWORD", "env-pass")
	t.Setenv("MY_OPENWAF_REDIS_DB", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer func() { _ = rt.Close() }()

	if rt.Redis == nil {
		t.Fatal("expected redis client to be initialized")
	}
	if rt.Config.RedisAddr != srv.Addr() {
		t.Fatalf("runtime redis addr = %q, want %q", rt.Config.RedisAddr, srv.Addr())
	}
	if rt.Config.RedisPassword != "secret-pass" {
		t.Fatalf("runtime redis password = %q, want secret-pass", rt.Config.RedisPassword)
	}
	if rt.Config.RedisDB != 7 {
		t.Fatalf("runtime redis db = %d, want 7", rt.Config.RedisDB)
	}

	commands := srv.Commands()
	if len(commands) == 0 {
		t.Fatal("expected mock redis server to receive commands")
	}

	var sawPing bool
	var sawAuth bool
	var sawSelect bool
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, "PING") {
			sawPing = true
		}
		if strings.HasPrefix(cmd, "AUTH ") {
			sawAuth = true
		}
		if strings.HasPrefix(cmd, "SELECT 7") {
			sawSelect = true
		}
	}
	if !sawPing {
		t.Fatalf("expected PING in commands, got %v", commands)
	}
	if !sawAuth {
		t.Fatalf("expected AUTH in commands, got %v", commands)
	}
	if !sawSelect {
		t.Fatalf("expected SELECT 7 in commands, got %v", commands)
	}
}

func TestNewRuntimeDisablesUnavailableStoredRedisAndContinuesStartup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "waf.db")
	logDBPath := filepath.Join(dir, "waf_logs.db")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve redis addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	seedRedisConfigDBAndOpen(t, dbPath, fmt.Sprintf(`{"enabled":true,"addr":"%s","db":0}`, addr))
	setRuntimeEnv(t, dbPath, logDBPath)
	t.Setenv("MY_OPENWAF_REDIS_ADDR", "")
	t.Setenv("MY_OPENWAF_REDIS_PASSWORD", "")
	t.Setenv("MY_OPENWAF_REDIS_DB", "0")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer func() { _ = rt.Close() }()

	if rt.Redis != nil {
		t.Fatal("expected redis client to be disabled when stored redis server is unavailable")
	}
	if rt.RedisKV == nil {
		t.Fatal("expected redis kv wrapper to remain available for hot reload")
	}
	if rt.RedisKV.Available() {
		t.Fatal("expected redis kv wrapper to be unavailable when stored redis server is unavailable")
	}
	if rt.Config.RedisAddr != addr {
		t.Fatalf("runtime redis addr = %q, want %q", rt.Config.RedisAddr, addr)
	}
	if rt.Config.RedisPassword != "" {
		t.Fatalf("runtime redis password = %q, want empty", rt.Config.RedisPassword)
	}
	if rt.Config.RedisDB != 0 {
		t.Fatalf("runtime redis db = %d, want 0", rt.Config.RedisDB)
	}
}

func TestNewRuntimeUsesStoredRedisConfigEvenWhenEnvRedisAddrIsInvalid(t *testing.T) {
	srv := startMockRedisServer(t)
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "waf.db")
	logDBPath := filepath.Join(dir, "waf_logs.db")
	seedRedisConfigDBAndOpen(t, dbPath, fmt.Sprintf(`{"enabled":true,"addr":"%s","password":"stored-pass","db":13}`, srv.Addr()))

	setRuntimeEnv(t, dbPath, logDBPath)
	t.Setenv("MY_OPENWAF_REDIS_ADDR", "bad-addr")
	t.Setenv("MY_OPENWAF_REDIS_PASSWORD", "env-pass")
	t.Setenv("MY_OPENWAF_REDIS_DB", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer func() { _ = rt.Close() }()

	if rt.Redis == nil {
		t.Fatal("expected redis client to be initialized from stored config")
	}
	if rt.Config.RedisAddr != srv.Addr() {
		t.Fatalf("runtime redis addr = %q, want %q", rt.Config.RedisAddr, srv.Addr())
	}
	if rt.Config.RedisPassword != "stored-pass" {
		t.Fatalf("runtime redis password = %q, want %q", rt.Config.RedisPassword, "stored-pass")
	}
	if rt.Config.RedisDB != 13 {
		t.Fatalf("runtime redis db = %d, want %d", rt.Config.RedisDB, 13)
	}
}
