package challenge

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/golang/freetype/truetype"
	"github.com/wenlng/go-captcha-assets/resources/fonts/fzshengsksjw"
	"github.com/wenlng/go-captcha-assets/resources/imagesv2"
	assetsTiles "github.com/wenlng/go-captcha-assets/resources/tiles"
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
		slide.WithGraphImages(loadSlideGraphImages()),
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

// generateClick 使用 go-captcha 生成点击验证码。
func (cm *CaptchaManager) generateClick(envKey []byte, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath(envKey, binding)
	}

	masterB64, thumbB64, data, err := cm.goCaptcha.GenerateClick()
	if err != nil {
		return cm.generateMath(envKey, binding)
	}

	// 序列化答案坐标
	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ChallengeSessionBinding: binding,
		ID:                      sessionID,
		Type:                    CaptchaTypeClick,
		Answer:                  string(answerJSON),
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(cm.timeoutValue()),
		EnvKey:                  envKey,
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeClick),
		MasterImg: masterB64,
		ThumbImg:  thumbB64,
		Prompt:    "请按顺序点击图中对应的文字",
		Width:     300,
		Height:    220,
		EnvKeyHex: EnvSessionKeyHex(envKey),
	}, nil
}

// generateSlide 使用 go-captcha 生成滑动验证码。
func (cm *CaptchaManager) generateSlide(envKey []byte, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath(envKey, binding)
	}

	masterB64, tileB64, data, err := cm.goCaptcha.GenerateSlide()
	if err != nil {
		return cm.generateMath(envKey, binding)
	}

	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ChallengeSessionBinding: binding,
		ID:                      sessionID,
		Type:                    CaptchaTypeSlide,
		Answer:                  string(answerJSON),
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(cm.timeoutValue()),
		EnvKey:                  envKey,
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeSlide),
		MasterImg: masterB64,
		ThumbImg:  tileB64,
		Prompt:    "请将滑块拖动到正确位置",
		Width:     300,
		Height:    220,
		EnvKeyHex: EnvSessionKeyHex(envKey),
	}, nil
}

// generateRotate 使用 go-captcha 生成旋转验证码。
func (cm *CaptchaManager) generateRotate(envKey []byte, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	if cm.goCaptcha == nil || !cm.goCaptcha.IsAvailable() {
		return cm.generateMath(envKey, binding)
	}

	masterB64, thumbB64, data, err := cm.goCaptcha.GenerateRotate()
	if err != nil {
		return cm.generateMath(envKey, binding)
	}

	answerJSON, _ := json.Marshal(data)
	sessionID := generateSessionID()
	session := &CaptchaSession{
		ChallengeSessionBinding: binding,
		ID:                      sessionID,
		Type:                    CaptchaTypeRotate,
		Answer:                  string(answerJSON),
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(cm.timeoutValue()),
		EnvKey:                  envKey,
	}
	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeRotate),
		MasterImg: masterB64,
		ThumbImg:  thumbB64,
		Prompt:    "请旋转图片至正确方向",
		Width:     220,
		Height:    220,
		EnvKeyHex: EnvSessionKeyHex(envKey),
	}, nil
}

// VerifyAdvanced 验证高级验证码答案（点击/滑动/旋转），支持容差。
func (cm *CaptchaManager) VerifyAdvanced(sessionID, answer string) bool {
	return cm.VerifyAdvancedWithBinding(sessionID, answer, ChallengeSessionBinding{})
}

// VerifyAdvancedWithBinding verifies a CAPTCHA response for the matched site.
func (cm *CaptchaManager) VerifyAdvancedWithBinding(sessionID, answer string, binding ChallengeSessionBinding) bool {
	ok, _ := cm.VerifyAdvancedSessionWithBinding(sessionID, answer, binding)
	return ok
}

// VerifyAdvancedSession 与 VerifyAdvanced 等价，但额外返回被校验的会话，
// 供调用方读取会话绑定的环境指纹密钥（EnvKey）执行浏览器/环境检查。
// 会话为一次性使用，无论校验成败都会在加载后立即删除。
// 返回的 *CaptchaSession 在会话不存在时为 nil。
func (cm *CaptchaManager) VerifyAdvancedSession(sessionID, answer string) (bool, *CaptchaSession) {
	return cm.VerifyAdvancedSessionWithBinding(sessionID, answer, ChallengeSessionBinding{})
}

// VerifyAdvancedSessionWithBinding atomically consumes the session only when
// its persisted site binding matches the current matched-site context.
func (cm *CaptchaManager) VerifyAdvancedSessionWithBinding(sessionID, answer string, binding ChallengeSessionBinding) (bool, *CaptchaSession) {
	session := cm.takeSessionWithBinding(sessionID, binding)
	if session == nil {
		return false, nil
	}

	if time.Now().After(session.ExpiresAt) {
		return false, session
	}

	tolerance := cm.getGoCaptchaTolerance(session.Type)

	switch session.Type {
	case CaptchaTypeClick:
		return verifyClickAnswer(session.Answer, answer, tolerance), session
	case CaptchaTypeSlide:
		return verifySlideAnswer(session.Answer, answer, tolerance), session
	case CaptchaTypeRotate:
		return verifyRotateAnswer(session.Answer, answer, tolerance), session
	case CaptchaTypeMath:
		return constantTimeEqualString(session.Answer, answer), session
	default:
		return constantTimeEqualString(session.Answer, answer), session
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

// ClickPoint 表示一个点击坐标点。
type ClickPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type clickPointAnswer struct {
	X *int `json:"x"`
	Y *int `json:"y"`
}

func verifyClickAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	if tolerance < 0 {
		return false
	}

	var storedDots map[string]*struct {
		Index  *int `json:"index"`
		X      *int `json:"x"`
		Y      *int `json:"y"`
		Width  *int `json:"width"`
		Height *int `json:"height"`
	}
	if err := json.Unmarshal([]byte(storedAnswer), &storedDots); err != nil {
		return false
	}

	var userPoints []clickPointAnswer
	if err := json.Unmarshal([]byte(userAnswer), &userPoints); err != nil {
		return false
	}
	if len(userPoints) == 0 || len(userPoints) != len(storedDots) {
		return false
	}

	type clickDot struct {
		index      int
		x, y, w, h int
	}
	dots := make([]clickDot, 0, len(storedDots))
	seenIndexes := make(map[int]struct{}, len(storedDots))
	for _, dot := range storedDots {
		if dot == nil || dot.Index == nil || dot.X == nil || dot.Y == nil || dot.Width == nil || dot.Height == nil {
			return false
		}
		if *dot.Index < 0 || *dot.Index >= len(storedDots) || *dot.X < 0 || *dot.Y < 0 || *dot.Width <= 0 || *dot.Height <= 0 {
			return false
		}
		if _, exists := seenIndexes[*dot.Index]; exists {
			return false
		}
		seenIndexes[*dot.Index] = struct{}{}
		dots = append(dots, clickDot{index: *dot.Index, x: *dot.X, y: *dot.Y, w: *dot.Width, h: *dot.Height})
	}
	sort.Slice(dots, func(i, j int) bool { return dots[i].index < dots[j].index })

	for i, dot := range dots {
		point := userPoints[i]
		if point.X == nil || point.Y == nil || *point.X < 0 || *point.Y < 0 {
			return false
		}
		if !click.Validate(*point.X, *point.Y, dot.x, dot.y, dot.w, dot.h, tolerance) {
			return false
		}
	}
	return true
}

func verifySlideAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	var stored struct {
		X  *int `json:"x"`
		Y  *int `json:"y"`
		DX *int `json:"dx"`
		DY *int `json:"dy"`
	}
	var provided struct {
		X *int `json:"x"`
		Y *int `json:"y"`
	}
	if err := json.Unmarshal([]byte(storedAnswer), &stored); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(userAnswer), &provided); err != nil {
		return false
	}
	if stored.X == nil || stored.Y == nil || stored.DX == nil || stored.DY == nil || provided.X == nil {
		return false
	}
	if *stored.X < 0 || *stored.Y < 0 || *stored.DX < 0 || *stored.DY < 0 || *provided.X < 0 {
		return false
	}

	providedY := 0
	if provided.Y != nil {
		if *provided.Y < 0 {
			return false
		}
		providedY = *provided.Y
	}
	absoluteX := *stored.DX + *provided.X
	absoluteY := *stored.DY + providedY
	return slide.Validate(absoluteX, absoluteY, *stored.X, *stored.Y, tolerance)
}

func verifyRotateAnswer(storedAnswer, userAnswer string, tolerance int) bool {
	var stored struct {
		Angle *int `json:"angle"`
	}
	var provided struct {
		Angle *int `json:"angle"`
	}
	if err := json.Unmarshal([]byte(storedAnswer), &stored); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(userAnswer), &provided); err != nil {
		return false
	}
	if stored.Angle == nil || provided.Angle == nil {
		return false
	}
	if *stored.Angle < 0 || *stored.Angle > 360 || *provided.Angle < 0 || *provided.Angle > 360 {
		return false
	}
	return rotate.Validate(*provided.Angle, *stored.Angle, tolerance)
}

func (p *GoCaptchaProvider) loadFont() (*truetype.Font, error) {
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
		"/usr/share/fonts/dejavu/DejaVuSans.ttf",
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

	// 使用官方内置字体作为最后回退，保证默认中文字符池在没有系统字体时仍可渲染。
	if font, err := fzshengsksjw.GetFont(); err == nil && font != nil {
		return font, nil
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

	if official, err := imagesv2.GetImages(); err == nil && len(official) > 0 {
		return official
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

// loadSlideGraphImages 优先加载官方图块资源，失败时使用程序化资源。
func loadSlideGraphImages() []*slide.GraphImage {
	if official, err := assetsTiles.GetTiles(); err == nil && len(official) > 0 {
		graphs := make([]*slide.GraphImage, 0, len(official))
		for _, graph := range official {
			if graph == nil || graph.OverlayImage == nil || graph.ShadowImage == nil || graph.MaskImage == nil {
				continue
			}
			graphs = append(graphs, &slide.GraphImage{
				OverlayImage: graph.OverlayImage,
				ShadowImage:  graph.ShadowImage,
				MaskImage:    graph.MaskImage,
			})
		}
		if len(graphs) > 0 {
			return graphs
		}
	}
	return generateSlideGraphImages()
}

// generateSlideGraphImages 生成滑动验证码所需的图块、阴影和遮罩资源。
// go-captcha v2.0.5 不会为滑动验证码自动创建图块资源；缺少这些资源时
// Generate 会返回 graph image is invalid，调用方随后回退到数学验证码。
func generateSlideGraphImages() []*slide.GraphImage {
	const size = 70
	bounds := image.Rect(0, 0, size, size)

	overlay := image.NewNRGBA(bounds)
	shadow := image.NewNRGBA(bounds)
	mask := image.NewNRGBA(bounds)
	draw.Draw(overlay, bounds, &image.Uniform{C: color.NRGBA{R: 38, G: 99, B: 235, A: 255}}, image.Point{}, draw.Src)
	draw.Draw(shadow, bounds, &image.Uniform{C: color.NRGBA{R: 15, G: 23, B: 42, A: 180}}, image.Point{}, draw.Src)
	draw.Draw(mask, bounds, &image.Uniform{C: color.NRGBA{R: 255, G: 255, B: 255, A: 255}}, image.Point{}, draw.Src)

	return []*slide.GraphImage{{
		OverlayImage: overlay,
		ShadowImage:  shadow,
		MaskImage:    mask,
	}}
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
