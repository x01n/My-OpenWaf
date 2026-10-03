package challenge

import "testing"

// healthyFingerprint 构造一份各维度全部通过的基线指纹（base score 为 0），
// 使完整性字段成为唯一的扣分来源，便于精确断言 +20 贡献。
func healthyFingerprint() *EnvFingerprint {
	return &EnvFingerprint{
		ChromePresent:        true,
		PluginsCount:         2,
		Languages:            "zh-CN",
		CanvasHash:           "abc",
		WebGLRenderer:        "NVIDIA GeForce RTX 3090",
		ScreenWidth:          1920,
		ScreenHeight:         1080,
		HardwareConcur:       8,
		ColorDepth:           24,
		PixelRatio:           1.0,
		AudioHash:            "audio",
		SessionStorage:       true,
		IndexedDB:            true,
		CookieEnabled:        true,
		PlatformStr:          "Win32",
		FontCount:            10,
		WebAssembly:          true,
		ServiceWorker:        true,
		MediaDevices:         true,
		IntersectionObserver: true,
		WebGL2Support:        true,
		ScreenConsistency:    true,
		TimezoneConsistency:  true,
		LanguageConsistency:  true,
		MathConsistency:      true,
	}
}

func TestValidateEnvFingerprintObjIntegrityLowAddsTwenty(t *testing.T) {
	if got := ValidateEnvFingerprint(healthyFingerprint()); got.Score != 0 {
		t.Fatalf("healthy baseline score = %d, want 0, reasons = %v", got.Score, got.Reasons)
	}
	objOne := int64(1)
	fp := healthyFingerprint()
	fp.ObjIntegrity = &objOne
	got := ValidateEnvFingerprint(fp)
	if got.Score != 20 {
		t.Fatalf("obj_integrity=1 score = %d, want 20", got.Score)
	}
	if !reasonsContain(got.Reasons, "window/document") {
		t.Errorf("reasons = %v, want 'window/document' reason", got.Reasons)
	}
	if reasonsContain(got.Reasons, "navigator prototype") {
		t.Errorf("reasons = %v, proto reason must be absent when only obj_integrity is set", got.Reasons)
	}
}

func TestValidateEnvFingerprintProtoIntegrityLowAddsTwenty(t *testing.T) {
	protoZero := int64(0)
	fp := healthyFingerprint()
	fp.ProtoIntegrity = &protoZero
	got := ValidateEnvFingerprint(fp)
	if got.Score != 20 {
		t.Fatalf("proto_integrity=0 score = %d, want 20", got.Score)
	}
	if !reasonsContain(got.Reasons, "navigator prototype") {
		t.Errorf("reasons = %v, want 'navigator prototype' reason", got.Reasons)
	}
	if reasonsContain(got.Reasons, "window/document") {
		t.Errorf("reasons = %v, obj reason must be absent when only proto_integrity is set", got.Reasons)
	}
}

func TestValidateEnvFingerprintIntegrityNilNotScored(t *testing.T) {
	// 旧 wasm 信封缺少新字段（nil 指针）时必须与基线判分完全一致。
	base := ValidateEnvFingerprint(healthyFingerprint())
	got := ValidateEnvFingerprint(healthyFingerprint())
	if got.Score != base.Score {
		t.Errorf("nil integrity score = %d, want %d", got.Score, base.Score)
	}
	if reasonsContain(got.Reasons, "window/document") || reasonsContain(got.Reasons, "navigator prototype") {
		t.Errorf("reasons = %v, nil integrity fields must not contribute reasons", got.Reasons)
	}
}

func TestValidateEnvFingerprintIntegrityFullScoresLikeNil(t *testing.T) {
	objFull, protoFull := int64(2), int64(2)
	full := healthyFingerprint()
	full.ObjIntegrity = &objFull
	full.ProtoIntegrity = &protoFull
	got := ValidateEnvFingerprint(full)
	want := ValidateEnvFingerprint(healthyFingerprint())
	if got.Score != want.Score {
		t.Fatalf("full integrity score = %d, want %d (same as legacy envelope)", got.Score, want.Score)
	}
	if reasonsContain(got.Reasons, "window/document") || reasonsContain(got.Reasons, "navigator prototype") {
		t.Errorf("reasons = %v, full integrity must not contribute reasons", got.Reasons)
	}
}

// reasonsContain 检查 reasons 切片中是否存在包含子串的条目。
func reasonsContain(reasons []string, substr string) bool {
	for _, reason := range reasons {
		if indexOfSubstr(reason, substr) {
			return true
		}
	}
	return false
}

// indexOfSubstr 朴素子串匹配，避免对 reason 短文本引入 strings 依赖或误用大小写折叠。
func indexOfSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
