package redis

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	goredis "github.com/redis/go-redis/v9"
)

type testConfigSyncRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	commands []string
	subs     map[string]map[*testConfigSyncRedisConn]struct{}
}

type testConfigSyncRedisConn struct {
	conn     net.Conn
	mu       sync.Mutex
	channels map[string]struct{}
}

func startTestConfigSyncRedisServer(t *testing.T) *testConfigSyncRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock redis: %v", err)
	}

	srv := &testConfigSyncRedisServer{
		ln:   ln,
		subs: make(map[string]map[*testConfigSyncRedisConn]struct{}),
	}
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

func (s *testConfigSyncRedisServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *testConfigSyncRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *testConfigSyncRedisServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *testConfigSyncRedisServer) record(args []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, strings.Join(args, " "))
}

func (s *testConfigSyncRedisServer) addSubscriber(channel string, c *testConfigSyncRedisConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs[channel] == nil {
		s.subs[channel] = make(map[*testConfigSyncRedisConn]struct{})
	}
	s.subs[channel][c] = struct{}{}
}

func (s *testConfigSyncRedisServer) removeSubscriber(channel string, c *testConfigSyncRedisConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subs, ok := s.subs[channel]; ok {
		delete(subs, c)
		if len(subs) == 0 {
			delete(s.subs, channel)
		}
	}
}

func (s *testConfigSyncRedisServer) subscribers(channel string) []*testConfigSyncRedisConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.subs[channel]
	out := make([]*testConfigSyncRedisConn, 0, len(subs))
	for c := range subs {
		out = append(out, c)
	}
	return out
}

func (s *testConfigSyncRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	c := &testConfigSyncRedisConn{
		conn:     conn,
		channels: make(map[string]struct{}),
	}
	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArgs(reader)
		if err != nil {
			for channel := range c.channels {
				s.removeSubscriber(channel, c)
			}
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
		case "SUBSCRIBE":
			if len(args) < 2 {
				_, _ = conn.Write([]byte("-ERR wrong number of arguments for 'subscribe' command\r\n"))
				continue
			}
			for _, channel := range args[1:] {
				s.addSubscriber(channel, c)
				c.channels[channel] = struct{}{}
				_, _ = fmt.Fprintf(conn, "*3\r\n$9\r\nsubscribe\r\n$%d\r\n%s\r\n:%d\r\n", len(channel), channel, len(c.channels))
			}
		case "UNSUBSCRIBE":
			channels := args[1:]
			if len(channels) == 0 {
				channels = make([]string, 0, len(c.channels))
				for channel := range c.channels {
					channels = append(channels, channel)
				}
			}
			for _, channel := range channels {
				s.removeSubscriber(channel, c)
				delete(c.channels, channel)
				_, _ = fmt.Fprintf(conn, "*3\r\n$11\r\nunsubscribe\r\n$%d\r\n%s\r\n:%d\r\n", len(channel), channel, len(c.channels))
			}
		case "PUBLISH":
			if len(args) < 3 {
				_, _ = conn.Write([]byte(":0\r\n"))
				continue
			}
			count := s.publish(args[1], args[2])
			_, _ = fmt.Fprintf(conn, ":%d\r\n", count)
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func (s *testConfigSyncRedisServer) publish(channel, payload string) int {
	subs := s.subscribers(channel)
	for _, c := range subs {
		c.sendMessage(channel, payload)
	}
	return len(subs)
}

func (c *testConfigSyncRedisConn) sendMessage(channel, payload string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = fmt.Fprintf(c.conn, "*3\r\n$7\r\nmessage\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(channel), channel, len(payload), payload)
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

	var count int
	if _, err := fmt.Sscanf(line[1:], "%d", &count); err != nil {
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

		var length int
		if _, err := fmt.Sscanf(header[1:], "%d", &length); err != nil {
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

func waitForConfigSyncCommand(t *testing.T, srv *testConfigSyncRedisServer, prefix string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, command := range srv.Commands() {
			if strings.HasPrefix(strings.ToUpper(command), strings.ToUpper(prefix)) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not observe redis command with prefix %q", prefix)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConfigSyncSkipsOwnPublishAndAcceptsForeignPublish(t *testing.T) {
	srv := startTestConfigSyncRedisServer(t)
	t.Cleanup(srv.Close)

	clientA := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	clientB := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncA := NewConfigSync(clientA, log, "node-a")
	syncB := NewConfigSync(clientB, log, "node-b")
	if syncA == nil || syncB == nil {
		t.Fatal("expected config sync handlers")
	}
	t.Cleanup(syncA.Close)
	t.Cleanup(syncB.Close)

	var reloadCount atomic.Int32
	go syncA.Subscribe(func() error {
		reloadCount.Add(1)
		return nil
	})

	waitForConfigSyncCommand(t, srv, "SUBSCRIBE")

	syncA.PublishReload()
	time.Sleep(200 * time.Millisecond)
	if got := reloadCount.Load(); got != 0 {
		t.Fatalf("self-published reload should be ignored, got %d callbacks", got)
	}

	syncB.PublishReload()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := reloadCount.Load(); got == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("foreign publish did not trigger reload callback, commands=%#v", srv.Commands())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
