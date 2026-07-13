package accessgate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthFlow 管理 OAuth2/OIDC 认证流程。
type OAuthFlow struct {
	ProviderID   uint
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Issuer       string
	Scopes       []string
	RedirectURI  string
	UsePKCE      bool
}

// OAuthState 存储 OAuth 流程中间状态。
type OAuthState struct {
	State        string
	CodeVerifier string
	SiteID       uint
	ProviderID   uint
	ReturnURL    string
	ExpiresAt    time.Time
}

// OAuthStateStore 管理 OAuth state。
type OAuthStateStore interface {
	Save(state *OAuthState) error
	Get(stateParam string) (*OAuthState, error)
	Delete(stateParam string) error
	CleanExpired() error
}

// MemoryOAuthStateStore 内存实现。
type MemoryOAuthStateStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
}

// NewMemoryOAuthStateStore 创建内存 OAuth state 存储。
func NewMemoryOAuthStateStore() *MemoryOAuthStateStore {
	return &MemoryOAuthStateStore{
		states: make(map[string]*OAuthState),
	}
}

func (s *MemoryOAuthStateStore) Save(state *OAuthState) error {
	s.mu.Lock()
	s.states[state.State] = state
	s.mu.Unlock()
	return nil
}

func (s *MemoryOAuthStateStore) Get(stateParam string) (*OAuthState, error) {
	s.mu.RLock()
	st, ok := s.states[stateParam]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	if time.Now().After(st.ExpiresAt) {
		s.mu.Lock()
		delete(s.states, stateParam)
		s.mu.Unlock()
		return nil, nil
	}
	return st, nil
}

func (s *MemoryOAuthStateStore) Delete(stateParam string) error {
	s.mu.Lock()
	delete(s.states, stateParam)
	s.mu.Unlock()
	return nil
}

func (s *MemoryOAuthStateStore) CleanExpired() error {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.states {
		if now.After(v.ExpiresAt) {
			delete(s.states, k)
		}
	}
	s.mu.Unlock()
	return nil
}

// StartAuthFlow 生成 OAuth 授权 URL。
func (f *OAuthFlow) StartAuthFlow(stateStore OAuthStateStore, siteID uint, returnURL string) (string, error) {
	stateParam, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	oauthState := &OAuthState{
		State:      stateParam,
		SiteID:     siteID,
		ProviderID: f.ProviderID,
		ReturnURL:  returnURL,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	params := url.Values{
		"client_id":     {f.ClientID},
		"redirect_uri":  {f.RedirectURI},
		"response_type": {"code"},
		"state":         {stateParam},
	}

	if len(f.Scopes) > 0 {
		params.Set("scope", strings.Join(f.Scopes, " "))
	} else {
		params.Set("scope", "openid email profile")
	}

	if f.UsePKCE {
		verifier := generateCodeVerifier()
		challenge := computeCodeChallenge(verifier)
		oauthState.CodeVerifier = verifier
		params.Set("code_challenge", challenge)
		params.Set("code_challenge_method", "S256")
	}

	if err := stateStore.Save(oauthState); err != nil {
		return "", err
	}

	authURL := f.AuthURL
	if authURL == "" && f.Issuer != "" {
		discovered, _, _, _ := DiscoverEndpoints(f.Issuer)
		if discovered != "" {
			authURL = discovered
		}
	}
	if authURL == "" {
		return "", fmt.Errorf("no auth URL configured")
	}

	separator := "?"
	if strings.Contains(authURL, "?") {
		separator = "&"
	}
	return authURL + separator + params.Encode(), nil
}

// ExchangeCode 用 authorization code 换取 access token。
func (f *OAuthFlow) ExchangeCode(code string, state *OAuthState) (string, error) {
	tokenURL := f.TokenURL
	if tokenURL == "" && f.Issuer != "" {
		_, discovered, _, _ := DiscoverEndpoints(f.Issuer)
		if discovered != "" {
			tokenURL = discovered
		}
	}
	if tokenURL == "" {
		return "", fmt.Errorf("no token URL configured")
	}

	params := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {f.RedirectURI},
		"client_id":    {f.ClientID},
	}
	if f.ClientSecret != "" {
		params.Set("client_secret", f.ClientSecret)
	}
	if state.CodeVerifier != "" {
		params.Set("code_verifier", state.CodeVerifier)
	}

	resp, err := http.PostForm(tokenURL, params)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("token error: %s", tokenResp.Error)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return tokenResp.AccessToken, nil
}

// FetchUserInfo 获取用户信息，返回身份标识。
func (f *OAuthFlow) FetchUserInfo(accessToken string) (string, error) {
	userinfoURL := f.UserInfoURL
	if userinfoURL == "" && f.Issuer != "" {
		_, _, discovered, _ := DiscoverEndpoints(f.Issuer)
		if discovered != "" {
			userinfoURL = discovered
		}
	}
	if userinfoURL == "" {
		return "", fmt.Errorf("no userinfo URL configured")
	}

	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var info struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}

	if info.Email != "" {
		return info.Email, nil
	}
	if info.Name != "" {
		return info.Name, nil
	}
	if info.Sub != "" {
		return info.Sub, nil
	}
	return "unknown", nil
}

// DiscoverEndpoints 执行 OIDC 自动发现。
func DiscoverEndpoints(issuer string) (authURL, tokenURL, userinfoURL string, err error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("discovery returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", "", err
	}

	var config struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return "", "", "", err
	}

	return config.AuthorizationEndpoint, config.TokenEndpoint, config.UserinfoEndpoint, nil
}

// generateCodeVerifier 生成 PKCE code_verifier（43-128 字符）。
func generateCodeVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// computeCodeChallenge 计算 PKCE code_challenge (S256)。
func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateRandomString 生成指定字节数的随机 hex 字符串。
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
