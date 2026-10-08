package challenge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"sync"
	"time"

	rueidis "github.com/redis/rueidis"

	"My-OpenWaf/internal/waf/challenge/pow"
)

// ChainStepType 定义链式挑战单个步骤的类型。
type ChainStepType string

const (
	ChainStepEnv     ChainStepType = "env"
	ChainStepPoW     ChainStepType = "pow"
	ChainStepCaptcha ChainStepType = "captcha"
)

// ChainStepConfig 定义链式挑战流水线中的一个步骤。
type ChainStepConfig struct {
	Type        ChainStepType `json:"type"`
	Condition   string        `json:"condition,omitempty"`
	CaptchaType CaptchaType   `json:"captcha_type,omitempty"`
}

// ChainState 是进行中的链式挑战的服务端状态。
type ChainSessionInfo struct {
	ID          string `json:"id"`
	CurrentStep int    `json:"current_step"`
	StepCount   int    `json:"step_count"`
	OriginalURL string `json:"original_url"`
	CreatedAt   string `json:"started_at"`
}

type ChainState struct {
	ChallengeSessionBinding
	SessionID   string            `json:"session_id"`
	CurrentStep int               `json:"current_step"`
	Steps       []ChainStepConfig `json:"steps"`
	Scores      map[string]int    `json:"scores"`
	EnvScore    int               `json:"env_score"`
	EnvKey      []byte            `json:"env_key,omitempty"`
	OriginalURL string            `json:"original_url"`
	Nonce       string            `json:"nonce"`
	// Difficulty 是本会话签发时锁定的 PoW 难度。
	// 必须随会话保存：若在挑战进行中通过 Reconfigure 修改全局难度，
	// 用客户端已按旧难度算出的解去比对新难度会导致挑战永远无法通过。
	Difficulty int       `json:"difficulty"`
	CaptchaID  string    `json:"captcha_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// powDifficulty 返回会话锁定的 PoW 难度。强制化语义：难度缺失/非正即本会话损坏，返回 0。
func (s *ChainState) powDifficulty(fallback int) int {
	_ = fallback
	if s == nil || s.Difficulty <= 0 {
		return 0
	}
	return pow.ClampPoWDifficulty(s.Difficulty)
}

// chainStateTTL 是 chain 会话的有效期，Redis 与内存两条路径共用。
const chainStateTTL = 10 * time.Minute

// clone 返回 ChainState 的深拷贝。
// 内存模式下必须在存取时复制，否则 map 中的指针会被多个并发请求同时读写，
// 触发数据竞争乃至 fatal "concurrent map writes"。
func (s *ChainState) clone() *ChainState {
	if s == nil {
		return nil
	}
	out := *s
	out.Steps = append([]ChainStepConfig(nil), s.Steps...)
	out.Scores = make(map[string]int, len(s.Scores))
	for k, v := range s.Scores {
		out.Scores[k] = v
	}
	return &out
}

// chainSessionGate 为每个会话提供一把串行锁，保证 “读状态 → 推进状态机 → 写状态”
// 是原子的。使用引用计数在最后一个持有者释放时回收锁对象，避免 map 无限增长。
type chainSessionGate struct {
	mu    sync.Mutex
	locks map[string]*chainSessionGateEntry
}

type chainSessionGateEntry struct {
	mu   sync.Mutex
	refs int
}

func newChainSessionGate() *chainSessionGate {
	return &chainSessionGate{locks: make(map[string]*chainSessionGateEntry)}
}

func (g *chainSessionGate) lock(id string) {
	g.mu.Lock()
	entry, ok := g.locks[id]
	if !ok {
		entry = &chainSessionGateEntry{}
		g.locks[id] = entry
	}
	entry.refs++
	g.mu.Unlock()
	entry.mu.Lock()
}

func (g *chainSessionGate) unlock(id string) {
	g.mu.Lock()
	entry, ok := g.locks[id]
	if !ok {
		g.mu.Unlock()
		return
	}
	entry.refs--
	if entry.refs <= 0 {
		delete(g.locks, id)
	}
	g.mu.Unlock()
	entry.mu.Unlock()
}

// ChainChallengeManager 以状态机管理多步链式挑战。
type ChainChallengeManager struct {
	captcha     *CaptchaManager
	redis       rueidis.Client
	prefix      string
	difficulty  int
	captchaType CaptchaType
	steps       []ChainStepConfig
	mu          sync.RWMutex
	states      map[string]*ChainState
	gate        *chainSessionGate
	done        chan struct{}
	once        sync.Once
}

// NewChainChallengeManager 用默认步骤创建一个 ChainChallengeManager。
func NewChainChallengeManager(captcha *CaptchaManager, redis rueidis.Client) *ChainChallengeManager {
	cm := &ChainChallengeManager{
		captcha:     captcha,
		redis:       redis,
		prefix:      "owaf:chain:",
		difficulty:  4,
		captchaType: CaptchaTypeMath,
		steps:       normalizeChainStepsWithCaptchaType(defaultChainSteps(), CaptchaTypeMath),
		states:      make(map[string]*ChainState),
		gate:        newChainSessionGate(),
		done:        make(chan struct{}),
	}
	go cm.cleanupLoop()
	return cm
}

// Close 停止内存态清理协程。
func (cm *ChainChallengeManager) Close() {
	if cm == nil {
		return
	}
	cm.once.Do(func() { close(cm.done) })
}

// cleanupLoop 周期性回收过期的内存态 chain 会话。
// Redis 模式依靠键 TTL 过期，内存模式此前没有任何回收路径，
// 被放弃的挑战会话会永久驻留并保持有效。
func (cm *ChainChallengeManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cm.purgeExpiredStates(time.Now())
		case <-cm.done:
			return
		}
	}
}

// purgeExpiredStates 删除所有超过 chainStateTTL 的内存态会话。
func (cm *ChainChallengeManager) purgeExpiredStates(now time.Time) {
	cm.mu.Lock()
	for id, s := range cm.states {
		if now.Sub(s.CreatedAt) > chainStateTTL {
			delete(cm.states, id)
		}
	}
	if len(cm.states) == 0 {
		cm.states = make(map[string]*ChainState)
	}
	cm.mu.Unlock()
}

func defaultChainSteps() []ChainStepConfig {
	return []ChainStepConfig{
		{Type: ChainStepEnv, Condition: "all"},
		{Type: ChainStepPoW, Condition: "all"},
		{Type: ChainStepCaptcha, Condition: "all"},
	}
}

func normalizeChainSteps(steps []ChainStepConfig) []ChainStepConfig {
	return normalizeChainStepsWithCaptchaType(steps, CaptchaTypeMath)
}

// normalizeChainStepsWithCaptchaType 归一化链式步骤，并为未指定类型的 CAPTCHA 继承全局类型。
func normalizeChainStepsWithCaptchaType(steps []ChainStepConfig, inherited CaptchaType) []ChainStepConfig {
	inherited = normalizeChainCaptchaType(inherited)
	out := make([]ChainStepConfig, 0, len(steps))
	for _, step := range steps {
		switch step.Type {
		case ChainStepEnv, ChainStepPoW:
			step.CaptchaType = ""
			out = append(out, step)
		case ChainStepCaptcha:
			// CAPTCHA 是链式挑战的最终人工校验步骤，不得依据客户端环境分数条件跳过。
			step.Condition = "all"
			if step.CaptchaType == "" {
				step.CaptchaType = inherited
			} else {
				step.CaptchaType = normalizeChainCaptchaType(step.CaptchaType)
			}
			out = append(out, step)
		}
	}
	if len(out) == 0 {
		return normalizeChainStepsWithCaptchaType(defaultChainSteps(), inherited)
	}
	return out
}

func normalizeChainCaptchaType(t CaptchaType) CaptchaType {
	switch t {
	case CaptchaTypeMath, CaptchaTypeClick, CaptchaTypeSlide, CaptchaTypeRotate:
		return t
	default:
		return CaptchaTypeMath
	}
}

func (cm *ChainChallengeManager) Reconfigure(steps []ChainStepConfig, difficulty int) {
	cm.ReconfigureWithCaptchaType(steps, difficulty, CaptchaTypeMath)
}

// ReconfigureWithCaptchaType 更新链式步骤、PoW 难度和步骤级 CAPTCHA 的全局继承值。
func (cm *ChainChallengeManager) ReconfigureWithCaptchaType(steps []ChainStepConfig, difficulty int, captchaType CaptchaType) {
	if difficulty <= 0 {
		difficulty = 4
	}
	difficulty = pow.ClampPoWDifficulty(difficulty)
	captchaType = normalizeChainCaptchaType(captchaType)
	cm.mu.Lock()
	cm.steps = normalizeChainStepsWithCaptchaType(steps, captchaType)
	cm.difficulty = difficulty
	cm.captchaType = captchaType
	cm.mu.Unlock()
}

func (cm *ChainChallengeManager) redisClient() rueidis.Client {
	if cm == nil {
		return nil
	}
	cm.mu.RLock()
	client := cm.redis
	cm.mu.RUnlock()
	return client
}

func (cm *ChainChallengeManager) SetRedis(redis rueidis.Client) {
	if cm == nil {
		return
	}
	cm.mu.Lock()
	cm.redis = redis
	cm.mu.Unlock()
}

func (cm *ChainChallengeManager) configuredSteps() []ChainStepConfig {
	cm.mu.RLock()
	steps := append([]ChainStepConfig(nil), cm.steps...)
	captchaType := cm.captchaType
	cm.mu.RUnlock()
	return normalizeChainStepsWithCaptchaType(steps, captchaType)
}

func (cm *ChainChallengeManager) difficultyValue() int {
	cm.mu.RLock()
	difficulty := cm.difficulty
	cm.mu.RUnlock()
	if difficulty <= 0 {
		return 4
	}
	return difficulty
}

// StartChain 开始一次链式挑战，返回会话 ID 与首步的 HTML。
func (cm *ChainChallengeManager) StartChain(originalURL string) (string, string) {
	return cm.StartChainWithBinding(originalURL, ChallengeSessionBinding{})
}

// StartChainWithBinding 创建一个绑定到匹配站点的链式会话。
func (cm *ChainChallengeManager) StartChainWithBinding(originalURL string, binding ChallengeSessionBinding) (string, string) {
	sid := chainGenID()
	state := &ChainState{
		ChallengeSessionBinding: binding.normalized(),
		SessionID:               sid,
		CurrentStep:             0,
		Steps:                   cm.configuredSteps(),
		Scores:                  make(map[string]int),
		OriginalURL:             originalURL,
		Nonce:                   pow.GeneratePoWNonce(),
		Difficulty:              cm.difficultyValue(),
		CreatedAt:               time.Now(),
	}
	cm.saveChainState(state)
	return sid, cm.renderStepHTML(state)
}

/**
 * ChainStepOutcome 描述一次链式挑战提交的处理结果。
 *
 * 单看 (passed, redirectURL, nextHTML) 无法区分「步内校验失败、重新渲染当前步」
 * 与「当前步通过、渲染下一步」——两者都是 (false, "", html)。调用方若据此记录
 * 失败会误伤正常推进多步挑战的访客，故用本类型显式区分。
 */
type ChainStepOutcome struct {
	// Passed 为 true 表示整条链已全部通过。
	Passed bool
	// RedirectURL 仅在 Passed 时有意义。
	RedirectURL string
	// NextHTML 非空时应作为响应体返回给客户端。
	NextHTML string
	// Failed 为 true 表示本次提交未通过校验（含会话缺失与步内校验失败），
	// 调用方可据此计入失败次数。链内正常推进不会置位。
	Failed bool
}

// ProcessStepDetailed 与 ProcessStep 行为一致，但额外报告本次提交是否校验失败。
// 数据面应使用本方法，以便对失败重试做服务端侧限制。
func (cm *ChainChallengeManager) ProcessStepDetailed(sessionID string, formData map[string]string) ChainStepOutcome {
	return cm.ProcessStepDetailedWithBinding(sessionID, formData, ChallengeSessionBinding{})
}

// ProcessStepDetailedWithBinding 只为签发该链的站点推进链。
func (cm *ChainChallengeManager) ProcessStepDetailedWithBinding(sessionID string, formData map[string]string, binding ChallengeSessionBinding) ChainStepOutcome {
	passed, redirectURL, nextHTML, failed := cm.processStepWithBinding(sessionID, formData, binding)
	return ChainStepOutcome{
		Passed:      passed,
		RedirectURL: redirectURL,
		NextHTML:    nextHTML,
		Failed:      failed,
	}
}

// ProcessStep 已被删除（b0 A 类强制化：Deprecated 且零生产调用）。
// 数据面统一使用 ProcessStepDetailedWithBinding / ProcessStepDetailed。

// processStep 是实现主体，第四个返回值标识本次提交是否校验失败。
// 整个 “读状态 → 校验当前步骤 → 推进 → 写状态” 序列在会话级串行锁内完成，
// 保证并发提交同一会话时状态机只按一条路径推进，且通行结果最多产生一次。
func (cm *ChainChallengeManager) processStepWithBinding(sessionID string, formData map[string]string, binding ChallengeSessionBinding) (bool, string, string, bool) {
	if sessionID == "" {
		return false, "", "", true
	}
	cm.gate.lock(sessionID)
	defer cm.gate.unlock(sessionID)

	state := cm.takeChainStateWithBinding(sessionID, binding)
	if state == nil {
		return false, "", "", true
	}
	if state.CurrentStep >= len(state.Steps) {
		return true, state.OriginalURL, "", false
	}
	step := state.Steps[state.CurrentStep]
	switch step.Type {
	case ChainStepEnv:
		envFP := DecryptEnvFingerprintWithAAD(
			formData["env_fp"],
			state.EnvKey,
			EnvFingerprintAAD("chain", state.SessionID, state.ChallengeSessionBinding),
		)
		if envFP == nil {
			state.EnvKey = nil
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state), true
		}
		result := ValidateEnvFingerprint(envFP)
		state.EnvScore = result.Score
		state.Scores["env"] = result.Score
		state.EnvKey = nil
		if !result.Pass {
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state), true
		}
	case ChainStepPoW:
		hash := formData["pow_hash"]
		counterStr := strings.TrimSpace(formData["pow_counter"])
		if counterStr == "" {
			state.Nonce = pow.GeneratePoWNonce()
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state), true
		}
		counter, err := strconv.ParseInt(counterStr, 10, 64)
		if err != nil || counter < 0 || !pow.VerifyPoW(state.Nonce, counter, hash, state.powDifficulty(cm.difficultyValue())) {
			state.Nonce = pow.GeneratePoWNonce()
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state), true
		}
		state.Scores["pow"] = 0
	case ChainStepCaptcha:
		answer := formData["captcha_answer"]
		if state.CaptchaID == "" || !cm.captcha.VerifyAdvancedWithBinding(state.CaptchaID, answer, state.ChallengeSessionBinding) {
			ch, _ := cm.captcha.GenerateWithBinding(normalizeChainCaptchaType(step.CaptchaType), false, state.ChallengeSessionBinding)
			if ch != nil {
				state.CaptchaID = ch.SessionID
			}
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state), true
		}
		state.Scores["captcha"] = 0
	}
	state.CurrentStep++
	for state.CurrentStep < len(state.Steps) {
		ns := state.Steps[state.CurrentStep]
		if cm.shouldRunStep(ns, state) {
			break
		}
		state.CurrentStep++
	}
	if state.CurrentStep >= len(state.Steps) {
		return true, state.OriginalURL, "", false
	}
	ns := state.Steps[state.CurrentStep]
	if ns.Type == ChainStepPoW {
		state.Nonce = pow.GeneratePoWNonce()
	} else if ns.Type == ChainStepCaptcha {
		ch, _ := cm.captcha.GenerateWithBinding(normalizeChainCaptchaType(ns.CaptchaType), false, state.ChallengeSessionBinding)
		if ch != nil {
			state.CaptchaID = ch.SessionID
		}
	}
	cm.saveChainState(state)
	return false, "", cm.renderStepHTML(state), false
}

func (cm *ChainChallengeManager) shouldRunStep(step ChainStepConfig, state *ChainState) bool {
	if step.Type == ChainStepCaptcha {
		return true
	}
	cond := step.Condition
	if cond == "" || cond == "all" {
		return true
	}
	var threshold int
	if n, _ := fmt.Sscanf(cond, "env_score>%d", &threshold); n == 1 {
		return state.EnvScore > threshold
	}
	if n, _ := fmt.Sscanf(cond, "env_score<%d", &threshold); n == 1 {
		return state.EnvScore < threshold
	}
	if n, _ := fmt.Sscanf(cond, "score>%d", &threshold); n == 1 {
		total := 0
		for _, s := range state.Scores {
			total += s
		}
		return total > threshold
	}
	return true
}

var chainPageTmpl = template.Must(template.ParseFS(challengePageFS, "templates/chain.html"))

type chainCaptchaPageData struct {
	Type        string
	MasterImg   template.URL
	ThumbImg    template.URL
	Prompt      string
	SlideWidth  int
	IsClick     bool
	IsSlide     bool
	IsRotate    bool
	CaptchaData string
	KeyHex      string
}

type chainPageData struct {
	StepNum   int
	Total     int
	Dots      []string
	SessionID string
	IsEnv     bool
	IsPoW     bool
	IsCaptcha bool
	EnvJS     template.JS
	PowJS     template.JS
	Captcha   *chainCaptchaPageData
	// WasmURL / GlueURL 带内容派生版本串（与 /__owaf/* 的 immutable 缓存配对）。
	WasmURL string
	GlueURL string
}

func newChainCaptchaPageData(ch *CaptchaChallenge) *chainCaptchaPageData {
	if ch == nil || ch.CaptchaData == "" {
		return nil
	}
	captchaType := CaptchaType(ch.Type)
	return &chainCaptchaPageData{
		Type:        ch.Type,
		Prompt:      ch.Prompt,
		SlideWidth:  firstPositiveInt(ch.Width, 360),
		IsClick:     captchaType == CaptchaTypeClick,
		IsSlide:     captchaType == CaptchaTypeSlide,
		IsRotate:    captchaType == CaptchaTypeRotate,
		CaptchaData: ch.CaptchaData,
		KeyHex:      ch.EnvKeyHex,
	}
}

func (cm *ChainChallengeManager) renderStepHTML(state *ChainState) string {
	if state.CurrentStep >= len(state.Steps) {
		return ""
	}
	step := state.Steps[state.CurrentStep]
	data := chainPageData{
		StepNum:   state.CurrentStep + 1,
		Total:     len(state.Steps),
		SessionID: state.SessionID,
		Dots:      make([]string, len(state.Steps)),
		WasmURL:   pow.PowWasmURL(),
		GlueURL:   pow.PowGlueURL(),
	}
	for i := range state.Steps {
		className := "sd"
		if i < state.CurrentStep {
			className += " done"
		} else if i == state.CurrentStep {
			className += " active"
		}
		data.Dots[i] = className
	}

	switch step.Type {
	case ChainStepEnv:
		data.IsEnv = true
		envKey := GenerateEnvSessionKey()
		if len(envKey) != envSessionKeySize {
			return ""
		}
		state.EnvKey = envKey
		data.EnvJS = template.JS(EnvCheckJSEncrypted(
			EnvSessionKeyHex(envKey),
			EnvFingerprintAAD("chain", state.SessionID, state.ChallengeSessionBinding),
		))
		if data.EnvJS == "" {
			return ""
		}
		cm.saveChainState(state)
	case ChainStepPoW:
		data.IsPoW = true
		data.PowJS = template.JS(pow.GeneratePoWWASMScript(state.powDifficulty(state.Difficulty), state.Nonce))
	case ChainStepCaptcha:
		data.IsCaptcha = true
		captchaChallenge, _ := cm.captcha.GenerateWithBinding(normalizeChainCaptchaType(step.CaptchaType), false, state.ChallengeSessionBinding)
		if captchaChallenge != nil {
			state.CaptchaID = captchaChallenge.SessionID
			cm.saveChainState(state)
			data.Captcha = newChainCaptchaPageData(captchaChallenge)
		}
	default:
		return ""
	}

	var buf bytes.Buffer
	if err := chainPageTmpl.ExecuteTemplate(&buf, "chain.html", data); err != nil {
		return "<!DOCTYPE html><html><body><p>Unable to render security verification.</p></body></html>"
	}
	return buf.String()
}

func chainGenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (cm *ChainChallengeManager) ListSessions() []ChainSessionInfo {
	if cm == nil {
		return nil
	}
	if cm.redisClient() != nil {
		return cm.listRedisSessions()
	}
	now := time.Now()
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	sessions := make([]ChainSessionInfo, 0, len(cm.states))
	for _, state := range cm.states {
		if now.Sub(state.CreatedAt) > chainStateTTL {
			continue
		}
		sessions = append(sessions, chainSessionInfoFromState(state))
	}
	return sessions
}

func (cm *ChainChallengeManager) DeleteSession(id string) bool {
	if cm == nil || strings.TrimSpace(id) == "" {
		return false
	}
	if cm.loadChainState(id) == nil {
		return false
	}
	cm.deleteChainState(id)
	return true
}

func (cm *ChainChallengeManager) listRedisSessions() []ChainSessionInfo {
	redis := cm.redisClient()
	if redis == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sessions := make([]ChainSessionInfo, 0)
	var cursor uint64
	for {
		entry, serr := redis.Do(ctx, redis.B().Scan().Cursor(cursor).Match(cm.prefix+"*").Count(100).Build()).AsScanEntry()
		if serr != nil {
			break
		}
		for _, k := range entry.Elements {
			data, gerr := redis.Do(ctx, redis.B().Get().Key(k).Build()).AsBytes()
			if gerr != nil {
				continue
			}
			var state ChainState
			if json.Unmarshal(data, &state) != nil {
				continue
			}
			sessions = append(sessions, chainSessionInfoFromState(&state))
		}
		cursor = entry.Cursor
		if cursor == 0 {
			break
		}
	}
	return sessions
}

func chainSessionInfoFromState(state *ChainState) ChainSessionInfo {
	if state == nil {
		return ChainSessionInfo{}
	}
	return ChainSessionInfo{
		ID:          state.SessionID,
		CurrentStep: state.CurrentStep,
		StepCount:   len(state.Steps),
		OriginalURL: state.OriginalURL,
		CreatedAt:   state.CreatedAt.Format(time.RFC3339),
	}
}

// saveChainState 持久化会话状态。内存模式下存入深拷贝，
// 调用方之后继续修改本地状态不会影响已保存的快照。
func (cm *ChainChallengeManager) saveChainState(state *ChainState) {
	if redis := cm.redisClient(); redis != nil {
		data, _ := json.Marshal(state)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := redis.Do(ctx, redis.B().Set().Key(cm.prefix+state.SessionID).Value(string(data)).Px(chainStateTTL).Build()).Error(); err != nil {
			return
		}
		return
	}
	cm.mu.Lock()
	cm.states[state.SessionID] = state.clone()
	cm.mu.Unlock()
}

// loadChainState 读取会话状态。内存模式下返回深拷贝，并拒绝且回收已过期的会话。
func (cm *ChainChallengeManager) loadChainState(id string) *ChainState {
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		data, err := redis.Do(ctx, redis.B().Get().Key(cm.prefix+id).Build()).AsBytes()
		if err != nil {
			return nil
		}
		var state ChainState
		if json.Unmarshal(data, &state) != nil {
			return nil
		}
		if time.Since(state.CreatedAt) > chainStateTTL {
			cm.deleteChainState(id)
			return nil
		}
		return &state
	}
	cm.mu.Lock()
	state, ok := cm.states[id]
	if ok && time.Since(state.CreatedAt) > chainStateTTL {
		delete(cm.states, id)
		ok = false
	}
	cm.mu.Unlock()
	if !ok {
		return nil
	}
	return state.clone()
}

// takeChainStateWithBinding 在核对持久化的站点绑定后原子领取一份链状态。
// 非终态处理成功会再次存回更新后的状态；终态成功则有意让它保持已消费。
func (cm *ChainChallengeManager) takeChainStateWithBinding(id string, binding ChallengeSessionBinding) *ChainState {
	if id == "" {
		return nil
	}
	binding = binding.normalized()
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		raw, err := takeAndDeleteBoundScript.Exec(ctx, redis, []string{cm.prefix + id}, []string{strconv.FormatUint(uint64(binding.SiteID), 10), binding.Host, binding.Bind}).ToString()
		if err != nil || raw == "" {
			return nil
		}
		var state ChainState
		if json.Unmarshal([]byte(raw), &state) != nil {
			return nil
		}
		if time.Since(state.CreatedAt) > chainStateTTL {
			return nil
		}
		cm.mu.Lock()
		delete(cm.states, id)
		cm.mu.Unlock()
		return &state
	}

	cm.mu.Lock()
	state, ok := cm.states[id]
	if ok && time.Since(state.CreatedAt) > chainStateTTL {
		delete(cm.states, id)
		ok = false
	}
	if ok && state != nil && state.ChallengeSessionBinding.matches(binding) {
		delete(cm.states, id)
		state = state.clone()
	} else {
		ok = false
	}
	cm.mu.Unlock()
	if !ok {
		return nil
	}
	return state
}

func (cm *ChainChallengeManager) deleteChainState(id string) {
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		redis.Do(ctx, redis.B().Del().Key(cm.prefix+id).Build())
	}
	cm.mu.Lock()
	delete(cm.states, id)
	cm.mu.Unlock()
}
