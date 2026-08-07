package challenge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

func TestCaptchaSessionBindingRejectsOtherSiteWithoutConsumption(t *testing.T) {
	manager := NewCaptchaManager(nil, 0)
	defer manager.Close()

	issuer := ChallengeSessionBinding{SiteID: 1, Host: "site-a.example.com", Bind: ":80"}
	mismatches := []ChallengeSessionBinding{
		{SiteID: 2, Host: issuer.Host, Bind: issuer.Bind},
		{SiteID: issuer.SiteID, Host: "site-b.example.com", Bind: issuer.Bind},
		{SiteID: issuer.SiteID, Host: issuer.Host, Bind: ":81"},
	}
	const sessionID = "captcha-site-binding"
	manager.sessions[sessionID] = &CaptchaSession{
		ChallengeSessionBinding: issuer,
		ID:                      sessionID,
		Type:                    CaptchaTypeMath,
		Answer:                  "42",
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(time.Minute),
	}

	for _, binding := range mismatches {
		if ok, _ := manager.VerifyAdvancedSessionWithBinding(sessionID, "42", binding); ok {
			t.Fatalf("mismatched binding %#v must not redeem the CAPTCHA session", binding)
		}
	}
	if ok, _ := manager.VerifyAdvancedSessionWithBinding(sessionID, "42", issuer); !ok {
		t.Fatal("issuing site must retain the CAPTCHA session after cross-site rejection")
	}
}

func TestChainSessionBindingRejectsOtherSiteWithoutAdvance(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	manager := NewChainChallengeManager(captcha, nil)
	defer manager.Close()
	manager.Reconfigure([]ChainStepConfig{{Type: ChainStepEnv, Condition: "all"}}, 1)

	issuer := ChallengeSessionBinding{SiteID: 1, Host: "site-a.example.com", Bind: ":80"}
	other := ChallengeSessionBinding{SiteID: 2, Host: "site-b.example.com", Bind: ":80"}
	sessionID, _ := manager.StartChainWithBinding("/protected", issuer)

	if outcome := manager.ProcessStepDetailedWithBinding(sessionID, map[string]string{"env_fp": "{}"}, other); !outcome.Failed || outcome.Passed {
		t.Fatalf("cross-site chain outcome = %+v, want failed without pass", outcome)
	}
	envelope := chainEnvironmentEnvelope(t, manager, sessionID, issuer)
	if outcome := manager.ProcessStepDetailedWithBinding(sessionID, map[string]string{"env_fp": envelope}, issuer); !outcome.Passed || outcome.RedirectURL != "/protected" {
		t.Fatalf("issuing site chain outcome = %+v, want pass to protected URL", outcome)
	}
}

type challengeBindingRedisServer struct {
	ln net.Listener

	mu     sync.Mutex
	values map[string]string
}

func startChallengeBindingRedisServer(t *testing.T) *challengeBindingRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock Redis: %v", err)
	}

	srv := &challengeBindingRedisServer{
		ln:     ln,
		values: make(map[string]string),
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

func (s *challengeBindingRedisServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *challengeBindingRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *challengeBindingRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readChallengeBindingRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = io.WriteString(conn, "-ERR unknown command 'hello'\r\n")
		case "SET":
			if len(args) < 3 {
				_, _ = io.WriteString(conn, "-ERR wrong number of arguments for 'set' command\r\n")
				continue
			}
			s.mu.Lock()
			s.values[args[1]] = args[2]
			s.mu.Unlock()
			_, _ = io.WriteString(conn, "+OK\r\n")
		case "EVALSHA":
			_, _ = io.WriteString(conn, "-NOSCRIPT No matching script. Please use EVAL.\r\n")
		case "EVAL":
			result, err := s.takeBound(args)
			if err != nil {
				_, _ = fmt.Fprintf(conn, "-ERR %s\r\n", err)
				continue
			}
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(result), result)
		default:
			_, _ = io.WriteString(conn, "+OK\r\n")
		}
	}
}

func (s *challengeBindingRedisServer) takeBound(args []string) (string, error) {
	if len(args) != 7 || args[2] != "1" {
		return "", fmt.Errorf("unexpected EVAL arguments: %#v", args)
	}

	script := args[1]
	for _, fragment := range []string{"cjson.decode", "session.site_id", "session.host", "session.bind"} {
		if !strings.Contains(script, fragment) {
			return "", fmt.Errorf("bound session script does not compare %q", fragment)
		}
	}

	deleteIndex := strings.Index(script, "redis.call('DEL', KEYS[1])")
	bindingIndex := strings.Index(script, "session.bind")
	if deleteIndex < bindingIndex {
		return "", fmt.Errorf("bound session script deletes before binding comparison")
	}

	key, siteID, host, bind := args[3], args[4], args[5], args[6]
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, ok := s.values[key]
	if !ok {
		return "", nil
	}
	var binding ChallengeSessionBinding
	if err := json.Unmarshal([]byte(raw), &binding); err != nil {
		return "", err
	}
	if strconv.FormatUint(uint64(binding.SiteID), 10) != siteID || strings.ToLower(binding.Host) != strings.ToLower(host) || binding.Bind != bind {
		return "", nil
	}
	delete(s.values, key)
	return raw, nil
}

func readChallengeBindingRESPArgs(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
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
	for range count {
		header, err := reader.ReadString('\n')
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
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		if _, err := reader.Discard(2); err != nil {
			return nil, err
		}
		args = append(args, string(value))
	}
	return args, nil
}

func TestCaptchaRedisBindingRejectsMismatchAndConsumesOnce(t *testing.T) {
	srv := startChallengeBindingRedisServer(t)
	t.Cleanup(srv.Close)

	client := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	manager := NewCaptchaManager(nil, 0)
	manager.SetRedis(client)
	t.Cleanup(manager.Close)

	issuer := ChallengeSessionBinding{SiteID: 1, Host: "site-a.example.com", Bind: ":80"}
	const sessionID = "redis-captcha-site-binding"
	if err := manager.storeSession(&CaptchaSession{
		ChallengeSessionBinding: issuer,
		ID:                      sessionID,
		Type:                    CaptchaTypeMath,
		Answer:                  "42",
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("storeSession(): %v", err)
	}

	wrongSite := ChallengeSessionBinding{SiteID: 2, Host: issuer.Host, Bind: issuer.Bind}
	if ok, _ := manager.VerifyAdvancedSessionWithBinding(sessionID, "42", wrongSite); ok {
		t.Fatal("wrong binding must not redeem Redis-backed CAPTCHA session")
	}
	if ok, _ := manager.VerifyAdvancedSessionWithBinding(sessionID, "42", issuer); !ok {
		t.Fatal("correct binding must redeem session retained after mismatch")
	}
	if ok, _ := manager.VerifyAdvancedSessionWithBinding(sessionID, "42", issuer); ok {
		t.Fatal("correct binding must redeem a Redis-backed session only once")
	}
}
