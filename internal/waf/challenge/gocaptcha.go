package challenge

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	_ "image/png"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/freetype/truetype"
	gocaptcha "github.com/wenlng/go-captcha/v2"
	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/click"
	"github.com/wenlng/go-captcha/v2/rotate"
	"github.com/wenlng/go-captcha/v2/slide"
)

// GoCaptchaConfig 存储 GoCaptcha 相关配置。
type GoCaptchaConfig struct {
	Enabled         bool   `json:"enabled"`
	ResourceDir     string `json:"resource_dir"`      // 资源目录（字体、背景图）
	FontPath        string `json:"font_path"`         // 自定义字体路径
	ClickCharPool   string `json:"click_char_pool"`   // 点击验证码字符池（大字符集，每次随机选取）
	RandomCharCount int    `json:"random_char_count"` // 每次验证码从字符池随机选取的字符数量
	ClickTolerance  int    `json:"click_tolerance"`   // 点击容差 (px)
	SlideTolerance  int    `json:"slide_tolerance"`   // 滑动容差 (px)
	RotateTolerance int    `json:"rotate_tolerance"`  // 旋转容差 (度)
	ClickRangeMin   int    `json:"click_range_min"`   // 生成字符数最小值
	ClickRangeMax   int    `json:"click_range_max"`   // 生成字符数最大值
	VerifyRangeMin  int    `json:"verify_range_min"`  // 需要验证的字符数最小值
	VerifyRangeMax  int    `json:"verify_range_max"`  // 需要验证的字符数最大值
}

// defaultClickCharPool 包含常用汉字字符池，每次验证码从中随机选取子集。
const defaultClickCharPool = "天地人和风雨雷电山水花鸟春夏秋冬日月星辰" +
	"江河湖海金木水火土石云雾冰雪松竹梅兰菊荷" +
	"龙凤虎鹤鹰马牛羊鹿狮象猫犬狼熊豹鱼蝶蜂" +
	"剑盾弓箭刀枪棋琴书画诗词歌赋笔墨纸砚" +
	"仁义礼智信忠孝悌勇廉耻温良恭俭让" +
	"东西南北上下左右前后内外高低远近大小" +
	"红橙黄绿青蓝紫黑白灰金银铜铁" +
	"一二三四五六七八九十百千万亿" +
	"心手眼口耳鼻舌身意力气血骨肉"

// DefaultGoCaptchaConfig 返回默认的 GoCaptcha 配置。
func DefaultGoCaptchaConfig() GoCaptchaConfig {
	return GoCaptchaConfig{
		Enabled:         true,
		ResourceDir:     "./data/captcha",
		ClickCharPool:   defaultClickCharPool,
		RandomCharCount: 30,
		ClickTolerance:  20,
		SlideTolerance:  5,
		RotateTolerance: 10,
		ClickRangeMin:   4,
		ClickRangeMax:   6,
		VerifyRangeMin:  2,
		VerifyRangeMax:  4,
	}
}

// GoCaptchaProvider 封装 go-captcha 库的三种验证码生成器。
type GoCaptchaProvider struct {
	mu     sync.RWMutex
	config GoCaptchaConfig
	log    *slog.Logger

	clickCapt  click.Captcha
	slideCapt  slide.Captcha
	rotateCapt rotate.Captcha

	initialized bool
	initErr     error
}

// NewGoCaptchaProvider 创建 GoCaptcha 提供器实例。
func NewGoCaptchaProvider(cfg GoCaptchaConfig, log *slog.Logger) *GoCaptchaProvider {
	if log == nil {
		log = slog.Default()
	}
	p := &GoCaptchaProvider{
		config: cfg,
		log:    log,
	}
	p.init()
	return p
}

// IsAvailable 返回 GoCaptcha 是否成功初始化。
func (p *GoCaptchaProvider) IsAvailable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.initialized && p.initErr == nil
}

func (p *GoCaptchaProvider) init() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.config.Enabled {
		p.initErr = fmt.Errorf("gocaptcha disabled")
		return
	}

	// 加载字体
	font, err := p.loadFont()
	if err != nil {
		p.log.Warn("go-captcha 字体加载失败，将使用内置验证码", slog.Any("err", err))
		p.initErr = err
		return
	}

	// 生成默认背景图
	bgImages := p.generateBackgrounds()

	// 初始化点击验证码（使用随机字符子集）
	clickRangeMin := p.config.ClickRangeMin
	clickRangeMax := p.config.ClickRangeMax
	verifyRangeMin := p.config.VerifyRangeMin
	verifyRangeMax := p.config.VerifyRangeMax
	if clickRangeMin <= 0 {
		clickRangeMin = 4
	}
	if clickRangeMax <= clickRangeMin {
		clickRangeMax = clickRangeMin + 2
	}
	if verifyRangeMin <= 0 {
		verifyRangeMin = 2
	}
	if verifyRangeMax <= verifyRangeMin {
		verifyRangeMax = verifyRangeMin + 2
	}
	clickBuilder := gocaptcha.NewClickBuilder(
		click.WithRangeLen(option.RangeVal{Min: clickRangeMin, Max: clickRangeMax}),
		click.WithRangeVerifyLen(option.RangeVal{Min: verifyRangeMin, Max: verifyRangeMax}),
	)
	chars := p.randomSelectChars()
	clickBuilder.SetResources(
		click.WithChars(chars),
		click.WithFonts([]*truetype.Font{font}),
		click.WithBackgrounds(bgImages),
	)
	p.clickCapt = clickBuilder.Make()

	// 初始化滑动验证码
	slideBuilder := gocaptcha.NewSlideBuilder()
	slideBuilder.SetResources(
		slide.WithBackgrounds(bgImages),
	)
	p.slideCapt = slideBuilder.Make()

	// 初始化旋转验证码
	rotateBuilder := gocaptcha.NewRotateBuilder()
	rotateBuilder.SetResources(
		rotate.WithImages(bgImages),
	)
	p.rotateCapt = rotateBuilder.Make()

	p.initialized = true
	p.log.Info("go-captcha 初始化成功")
}

// GenerateClick 生成点击验证码。
func (p *GoCaptchaProvider) GenerateClick() (masterB64, thumbB64 string, data map[int]*click.Dot, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return "", "", nil, fmt.Errorf("go-captcha not initialized: %v", p.initErr)
	}

	captData, err := p.clickCapt.Generate()
	if err != nil {
		return "", "", nil, err
	}

	masterB64, err = captData.GetMasterImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("click master to base64: %w", err)
	}
	thumbB64, err = captData.GetThumbImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("click thumb to base64: %w", err)
	}
	data = captData.GetData()
	return
}

// GenerateSlide 生成滑动验证码。
func (p *GoCaptchaProvider) GenerateSlide() (masterB64, tileB64 string, data *slide.Block, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return "", "", nil, fmt.Errorf("go-captcha not initialized: %v", p.initErr)
	}

	captData, err := p.slideCapt.Generate()
	if err != nil {
		return "", "", nil, err
	}

	masterB64, err = captData.GetMasterImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("slide master to base64: %w", err)
	}
	tileB64, err = captData.GetTileImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("slide tile to base64: %w", err)
	}
	data = captData.GetData()
	return
}

// GenerateRotate 生成旋转验证码。
func (p *GoCaptchaProvider) GenerateRotate() (masterB64, thumbB64 string, data *rotate.Block, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return "", "", nil, fmt.Errorf("go-captcha not initialized: %v", p.initErr)
	}

	captData, err := p.rotateCapt.Generate()
	if err != nil {
		return "", "", nil, err
	}

	masterB64, err = captData.GetMasterImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("rotate master to base64: %w", err)
	}
	thumbB64, err = captData.GetThumbImage().ToBase64()
	if err != nil {
		return "", "", nil, fmt.Errorf("rotate thumb to base64: %w", err)
	}
	data = captData.GetData()
	return
}

// ── CaptchaManager 集成方法 ──

// generateClick 使用 go-captcha 生成点击验证码。
func (cm *CaptchaManager) generateClick() (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath()
	}

	masterB64, thumbB64, data, err := cm.goCaptcha.GenerateClick()
	if err != nil {
		return cm.generateMath()
	}

	// 序列化答案坐标
	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeClick,
		Answer:    string(answerJSON),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.timeoutValue()),
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeClick),
		MasterImg: "data:image/jpeg;base64," + masterB64,
		ThumbImg:  "data:image/png;base64," + thumbB64,
		Prompt:    "请按顺序点击图中对应的文字",
		Width:     300,
		Height:    240,
	}, nil
}

// generateSlide 使用 go-captcha 生成滑动验证码。
func (cm *CaptchaManager) generateSlide() (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath()
	}

	masterB64, tileB64, data, err := cm.goCaptcha.GenerateSlide()
	if err != nil {
		return cm.generateMath()
	}

	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeSlide,
		Answer:    string(answerJSON),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.timeoutValue()),
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeSlide),
		MasterImg: "data:image/jpeg;base64," + masterB64,
		ThumbImg:  "data:image/png;base64," + tileB64,
		Prompt:    "请将滑块拖动到正确位置",
		Width:     300,
		Height:    180,
	}, nil
}

// generateRotate 使用 go-captcha 生成旋转验证码。
func (cm *CaptchaManager) generateRotate() (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath()
	}

	masterB64, thumbB64, data, err := cm.goCaptcha.GenerateRotate()
	if err != nil {
		return cm.generateMath()
	}

	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeRotate,
		Answer:    string(answerJSON),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.timeoutValue()),
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeRotate),
		MasterImg: "data:image/png;base64," + masterB64,
		ThumbImg:  "data:image/png;base64," + thumbB64,
		Prompt:    "请旋转图片至正确方向",
		Width:     200,
		Height:    200,
	}, nil
}

// VerifyAdvanced 验证高级验证码答案（点击/滑动/旋转），支持容差。
func (cm *CaptchaManager) VerifyAdvanced(sessionID, answer string) bool {
	session, err := cm.loadSession(sessionID)
	if err != nil || session == nil {
		return false
	}
	cm.deleteSession(sessionID)

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	tolerance := cm.getGoCaptchaTolerance(session.Type)

	switch session.Type {
	case CaptchaTypeClick:
		return verifyClickAnswer(session.Answer, answer, tolerance)
	case CaptchaTypeSlide:
		return verifySlideAnswer(session.Answer, answer, tolerance)
	case CaptchaTypeRotate:
		return verifyRotateAnswer(session.Answer, answer, tolerance)
	case CaptchaTypeMath:
		return session.Answer == answer
	default:
		return session.Answer == answer
	}
}

func (cm *CaptchaManager) getGoCaptchaTolerance(t CaptchaType) int {
	if cm.goCaptcha == nil {
		return 20
	}
	switch t {
	case CaptchaTypeClick:
		return cm.goCaptcha.config.ClickTolerance
	case CaptchaTypeSlide:
		return cm.goCaptcha.config.SlideTolerance
	case CaptchaTypeRotate:
		return cm.goCaptcha.config.RotateTolerance
	default:
		return 20
	}
}

// ── 验证辅助函数 ──

// ClickPoint 表示一个点击坐标点。
type ClickPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func verifyClickAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	// 尝试解析 go-captcha 格式的点数据
	var storedDots map[string]interface{}
	if err := json.Unmarshal([]byte(storedAnswer), &storedDots); err != nil {
		return false
	}

	var userPoints []ClickPoint
	if err := json.Unmarshal([]byte(userAnswer), &userPoints); err != nil {
		return false
	}

	// 简化验证：检查用户点击数是否匹配
	if len(userPoints) != len(storedDots) {
		return false
	}

	// 对 go-captcha 生成的点数据进行坐标验证
	i := 0
	for _, dotRaw := range storedDots {
		if i >= len(userPoints) {
			return false
		}
		dotMap, ok := dotRaw.(map[string]interface{})
		if !ok {
			i++
			continue
		}
		expectedX := int(getFloat(dotMap, "x"))
		expectedY := int(getFloat(dotMap, "y"))
		dx := abs(userPoints[i].X - expectedX)
		dy := abs(userPoints[i].Y - expectedY)
		if dx > tolerance || dy > tolerance {
			return false
		}
		i++
	}
	return true
}

func verifySlideAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	var stored map[string]interface{}
	var provided map[string]interface{}
	if err := json.Unmarshal([]byte(storedAnswer), &stored); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(userAnswer), &provided); err != nil {
		return false
	}
	expectedX := int(getFloat(stored, "x"))
	providedX := int(getFloat(provided, "x"))
	return abs(providedX-expectedX) <= tolerance
}

func verifyRotateAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	var stored map[string]interface{}
	var provided map[string]interface{}
	if err := json.Unmarshal([]byte(storedAnswer), &stored); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(userAnswer), &provided); err != nil {
		return false
	}
	expectedAngle := int(getFloat(stored, "angle"))
	providedAngle := int(getFloat(provided, "angle"))
	diff := abs(providedAngle - expectedAngle)
	if diff > 180 {
		diff = 360 - diff
	}
	return diff <= tolerance
}

func getFloat(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	default:
		return 0
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ── 资源辅助函数 ──

func (p *GoCaptchaProvider) loadFont() (*truetype.Font, error) {
	// 尝试加载自定义字体
	fontPath := p.config.FontPath
	if fontPath == "" && p.config.ResourceDir != "" {
		fontPath = filepath.Join(p.config.ResourceDir, "fonts", "default.ttf")
	}

	if fontPath != "" {
		data, err := os.ReadFile(fontPath)
		if err == nil {
			font, err := truetype.Parse(data)
			if err == nil {
				return font, nil
			}
		}
	}

	// 尝试系统字体路径
	systemFonts := []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/TTF/DejaVuSans.ttf",
		"C:\\Windows\\Fonts\\msyh.ttc",
		"C:\\Windows\\Fonts\\simhei.ttf",
		"C:\\Windows\\Fonts\\arial.ttf",
	}
	for _, fp := range systemFonts {
		data, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		font, err := truetype.Parse(data)
		if err == nil {
			return font, nil
		}
	}

	return nil, fmt.Errorf("no font available")
}

func (p *GoCaptchaProvider) generateBackgrounds() []image.Image {
	// 尝试从资源目录加载背景图
	if p.config.ResourceDir != "" {
		bgDir := filepath.Join(p.config.ResourceDir, "backgrounds")
		entries, err := os.ReadDir(bgDir)
		if err == nil && len(entries) > 0 {
			var imgs []image.Image
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				fp := filepath.Join(bgDir, entry.Name())
				f, err := os.Open(fp)
				if err != nil {
					continue
				}
				img, _, err := image.Decode(f)
				f.Close()
				if err != nil {
					continue
				}
				imgs = append(imgs, img)
			}
			if len(imgs) > 0 {
				return imgs
			}
		}
	}

	// 生成程序化背景图
	return generateDefaultBackgrounds()
}

func generateDefaultBackgrounds() []image.Image {
	imgs := make([]image.Image, 3)
	for idx := range imgs {
		w, h := 300, 240
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		// 渐变色背景
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				r := uint8((180 + idx*20 + x*30/w) % 256)
				g := uint8((200 + idx*15 + y*20/h) % 256)
				b := uint8((220 + idx*10 + (x+y)*10/(w+h)) % 256)
				img.Set(x, y, color.RGBA{r, g, b, 255})
			}
		}
		// 添加纹理线条
		lineColor := color.RGBA{uint8(100 + idx*30), uint8(120 + idx*20), uint8(140 + idx*10), 80}
		for i := 0; i < w; i += 20 {
			for y := 0; y < h; y++ {
				img.Set(i, y, lineColor)
			}
		}
		for i := 0; i < h; i += 20 {
			for x := 0; x < w; x++ {
				img.Set(x, i, lineColor)
			}
		}
		imgs[idx] = img
	}
	return imgs
}

// randomSelectChars 从字符池中随机选取指定数量的字符，确保每次验证码字符不同。
func (p *GoCaptchaProvider) randomSelectChars() []string {
	pool := splitChars(p.config.ClickCharPool)
	if len(pool) == 0 {
		pool = splitChars(defaultClickCharPool)
	}
	count := p.config.RandomCharCount
	if count <= 0 || count > len(pool) {
		count = 30
	}
	if count > len(pool) {
		count = len(pool)
	}
	// Fisher-Yates 洗牌后取前 N 个
	shuffled := make([]string, len(pool))
	copy(shuffled, pool)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := randIntN(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	return shuffled[:count]
}

func splitChars(s string) []string {
	var result []string
	for _, ch := range s {
		result = append(result, string(ch))
	}
	return result
}
