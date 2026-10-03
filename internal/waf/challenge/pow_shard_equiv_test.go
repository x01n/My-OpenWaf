package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// deterministicRandReader 提供可重放的确定性字节流：每次新建实例都从
// 同一序列起点开始，使「重置后再调用」能逐字节再现上一次的随机性消耗。
type deterministicRandReader struct {
	seed byte
	step byte
}

func (r *deterministicRandReader) Read(p []byte) (int, error) {
	for i := range p {
		r.seed += r.step
		r.step++
		p[i] = r.seed
	}
	return len(p), nil
}

// replayRandFromStart 把 crypto/rand.Reader 换成全新的确定性流，
// 使接下来的 generatePoWScriptBody / GeneratePoWWASMScript 调用在
// 随机性消耗序列完全一致时产出逐字节相同的结果。
func replayRandFromStart(t *testing.T) {
	t.Helper()
	original := rand.Reader
	rand.Reader = &deterministicRandReader{step: 1}
	t.Cleanup(func() { rand.Reader = original })
}

// 编译期确认 deterministicRandReader 满足 io.Reader。
var _ io.Reader = (*deterministicRandReader)(nil)

// randNonceForTest 生成测试用的随机 nonce：大部分为随机 hex，
// 小部分覆盖空串边界；调用方按需取得空串用例。
func randNonceForTest(t *testing.T, allowEmpty bool) string {
	t.Helper()
	if allowEmpty && randIntN(8) == 0 {
		return ""
	}
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("crypto/rand failed: %v", err)
	}
	return hex.EncodeToString(b)
}

// difficultyForTest 生成难度用例：主域 1..7，并轮转覆盖 0/8/9 三个钳制边界。
func difficultyForTest(iteration int) []int {
	base := make([]int, 0, 12)
	for d := 1; d <= 7; d++ {
		base = append(base, d)
	}
	switch iteration % 3 {
	case 0:
		base = append(base, 0)
	case 1:
		base = append(base, 8)
	default:
		base = append(base, 9)
	}
	return base
}

// TestGeneratePoWScriptBodyMatchesLegacy 锁定拆分重构：在可重放的
// 确定性随机流（每轮重置）下，generatePoWScriptBody 与
// GeneratePoWWASMScript 必须逐字节相同。
func TestGeneratePoWScriptBodyMatchesLegacy(t *testing.T) {
	const rounds = 110
	for i := 0; i < rounds; i++ {
		for _, difficulty := range difficultyForTest(i) {
			nonce := randNonceForTest(t, i%5 == 0)
			// 每次对照都从同一随机流起点出发，两条生成路径的
			// 随机性消耗序列必须完全一致。
			replayRandFromStart(t)
			legacy := GeneratePoWWASMScript(difficulty, nonce)
			replayRandFromStart(t)
			body := generatePoWScriptBody(difficulty, nonce)
			if legacy != body {
				t.Fatalf(
					"output mismatch: difficulty=%d nonce=%q legacyLen=%d bodyLen=%d",
					difficulty, nonce, len(legacy), len(body),
				)
			}
		}
	}
}

// TestPowShardScriptRoundTripEquivalence 验证：分片化的生成步骤内部用的
// 是同一个 generatePoWScriptBody 产出（避免二次生成的随机差异），因此
// 正向解码校验改为逐字节 XOR 还原后与生成函数直接对照——先复位确定性
// 随机流，再先后调用生成函数与分片函数，两次生成完全一致。
func TestPowShardScriptRoundTripEquivalence(t *testing.T) {
	const rounds = 56
	for i := 0; i < rounds; i++ {
		for _, difficulty := range difficultyForTest(i) {
			nonce := randNonceForTest(t, i%5 == 0)
			replayRandFromStart(t)
			sharded := GeneratePoWShardedScript(difficulty, nonce)
			replayRandFromStart(t)
			expected := generatePoWScriptBody(difficulty, nonce)

			if fnv1a32(expected) != sharded.Checksum {
				t.Fatalf(
					"checksum mismatch: difficulty=%d nonce=%q got=%d want=%d",
					difficulty, nonce, sharded.Checksum, fnv1a32(expected),
				)
			}
			if len(sharded.BodyHexParts) != len(sharded.Keys) {
				t.Fatalf(
					"part/key count mismatch: difficulty=%d parts=%d keys=%d",
					difficulty, len(sharded.BodyHexParts), len(sharded.Keys),
				)
			}

			var assembled strings.Builder
			for idx, encoded := range sharded.BodyHexParts {
				raw, err := hex.DecodeString(encoded)
				if err != nil {
					t.Fatalf("hex decode failed: difficulty=%d part=%d err=%v", difficulty, idx, err)
				}
				piece := make([]byte, len(raw))
				for j, b := range raw {
					piece[j] = b ^ sharded.Keys[idx]
				}
				assembled.Write(piece)
			}
			got := assembled.String()
			if got != expected {
				t.Fatalf(
					"assembled body mismatch: difficulty=%d nonce=%q gotLen=%d wantLen=%d",
					difficulty, nonce, len(got), len(expected),
				)
			}
		}
	}
}

// TestPowShardPageScriptStaticShape 静态断言装配器结构：
// 必须包含 (0,eval).call(window, 与 Math.imul 子串。
func TestPowShardPageScriptStaticShape(t *testing.T) {
	sharded := GeneratePoWShardedScript(4, "static-shape-nonce")
	for _, marker := range []string{"(0,eval).call(window,", "Math.imul"} {
		if !strings.Contains(sharded.PageScript, marker) {
			t.Fatalf("PageScript missing marker %q", marker)
		}
	}
	if len(sharded.BodyHexParts) < powShardMinParts || len(sharded.BodyHexParts) > powShardMaxParts {
		t.Fatalf("shard count out of range: %d", len(sharded.BodyHexParts))
	}
}

// TestSplitPointsAssembleLosslessly 用含单双引号、换行、%q 转义的样例
// 直接调拆分函数，断言拼接恒等、片数在 3..5 且互不重叠。
func TestSplitPointsAssembleLosslessly(t *testing.T) {
	samples := []string{
		`func main(){println("hello")}`,
		"single-'quote' and double-\"quote\" mixed",
		"line\nbreaks\nand\ttabs",
		`%q-escaped:\t\n\"\\\x41中`,
		"",
		"a",
		"ab",
	}
	for i, sample := range samples {
		// 样例按字节长度分两类：长度 >= powShardMinParts 的正常域，
		// 长度不足的短输入域（含空串边界、单字节、双字节）。
		byteLen := len(sample)
		shortInput := byteLen < powShardMinParts
		for round := 0; round < 20; round++ {
			pieces := SplitPowShardBody(sample)
			if shortInput {
				// k 在函数内部被钳制到 length，且片数下限保底为 1：
				// 空串退回 1 片空串，Join 仍恒等。
				want := byteLen
				if want == 0 {
					want = 1
				}
				if len(pieces) != want {
					t.Fatalf("sample=%d piece count for short input: got=%d want=%d", i, len(pieces), want)
				}
			} else if len(pieces) < powShardMinParts || len(pieces) > powShardMaxParts {
				t.Fatalf("sample=%d piece count out of range: %d", i, len(pieces))
			}
			if got := strings.Join(pieces, ""); got != sample {
				t.Fatalf("sample=%d join mismatch: gotLen=%d wantLen=%d", i, len(got), len(sample))
			}
		}
	}

	const xsRounds = 40
	for round := 0; round < xsRounds; round++ {
		sample := generatePoWScriptBody(1+randIntN(7), randNonceForTest(t, false))
		pieces := SplitPowShardBody(sample)
		if got := strings.Join(pieces, ""); got != sample {
			t.Fatalf("real-body join mismatch at round=%d: gotLen=%d wantLen=%d", round, len(got), len(sample))
		}
	}
}

// TestGeneratePoWShardedEnvelopeEquivalence 锁定加密分片 v2 与既有
// generatePoWScriptBody 的同步关系：在可重放的确定性随机流下生成 v2
// 信封，Go 侧用 gm.Open 解回内层 JSON，逐片 base64url 解码 + XOR 还原
// 拼接后必须与重新生成的完整正文逐字节相等，CRC 用 fnv1a32 对照。
func TestGeneratePoWShardedEnvelopeEquivalence(t *testing.T) {
	const rounds = 48
	for i := 0; i < rounds; i++ {
		for _, difficulty := range difficultyForTest(i) {
			nonce := randNonceForTest(t, i%5 == 0)
			key := GenerateEnvSessionKey()

			replayRandFromStart(t)
			generated := generatePoWScriptBody(difficulty, nonce)
			replayRandFromStart(t)
			envelope, bootstrap, err := GeneratePoWShardedEnvelope(difficulty, nonce, key)
			if err != nil {
				t.Fatalf("GeneratePoWShardedEnvelope failed: difficulty=%d nonce=%q err=%v", difficulty, nonce, err)
			}
			if envelope == "" || bootstrap == "" {
				t.Fatalf("GeneratePoWShardedEnvelope returned empty output: difficulty=%d nonce=%q", difficulty, nonce)
			}
			if !strings.Contains(bootstrap, "vm_assemble_shards") || !strings.Contains(bootstrap, "__owaf_pow_error") || !strings.Contains(bootstrap, "(0,eval).call(window,") {
				t.Fatalf("page bootstrap missing VM assembly markers: %s", bootstrap)
			}

			raw, err := gm.Decode(envelope)
			if err != nil {
				t.Fatalf("envelope decode failed: difficulty=%d nonce=%q err=%v", difficulty, nonce, err)
			}
			plaintext, err := gm.Open(key[:16], raw, []byte(powShardsAAD), gm.DomainPowShards, true)
			if err != nil {
				t.Fatalf("envelope open failed: difficulty=%d nonce=%q err=%v", difficulty, nonce, err)
			}
			var shard PowShardEnvelope
			if err := json.Unmarshal(plaintext, &shard); err != nil {
				t.Fatalf("shard json unmarshal failed: difficulty=%d nonce=%q err=%v", difficulty, nonce, err)
			}
			if shard.V != int(gm.GMEnvelopeVersion) {
				t.Fatalf("shard version mismatch: difficulty=%d got=%d want=%d", difficulty, shard.V, gm.GMEnvelopeVersion)
			}
			if len(shard.Shards) < powShardMinParts || len(shard.Shards) > powShardMaxParts {
				t.Fatalf("shard count out of range: difficulty=%d got=%d", difficulty, len(shard.Shards))
			}

			var assembled strings.Builder
			for idx, item := range shard.Shards {
				encoded, err := base64.RawURLEncoding.DecodeString(item.Data)
				if err != nil {
					t.Fatalf("shard base64 decode failed: difficulty=%d part=%d err=%v", difficulty, idx, err)
				}
				piece := make([]byte, len(encoded))
				for j, b := range encoded {
					piece[j] = b ^ item.Key
				}
				assembled.Write(piece)
			}
			if got := assembled.String(); got != generated {
				t.Fatalf("assembled body mismatch: difficulty=%d nonce=%q gotLen=%d wantLen=%d", difficulty, nonce, len(got), len(generated))
			}
			wantCRC := strconv.FormatUint(uint64(fnv1a32(generated)), 10)
			if shard.CRC != wantCRC {
				t.Fatalf("crc mismatch: difficulty=%d nonce=%q got=%s want=%s", difficulty, nonce, shard.CRC, wantCRC)
			}
		}
	}
}
