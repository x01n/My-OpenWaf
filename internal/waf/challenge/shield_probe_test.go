package challenge

import "testing"

/**
 * TestShieldProbeSoftScore 锁服务端软信号加分口径：
 * 客户端只上报采集值（dt/auto），评分全部在服务端换算；
 * 非法/缺失 JSON 与清洗后的 auto 一律不得产生超预期加分。
 */
func TestShieldProbeSoftScore(t *testing.T) {
	cases := []struct {
		name      string
		probe     string
		wantScore int
		wantReas  int
	}{
		{"empty", "", 0, 0},
		{"malformed", `{"dt":`, 0, 0},
		{"non-object", `[1,2]`, 0, 0},
		{"dt only", `{"dt":true}`, 5, 1},
		{"auto only", `{"dt":false,"auto":"webdriver"}`, 10, 1},
		{"both", `{"dt":true,"auto":"headless"}`, 15, 2},
		{"auto sanitized", `{"dt":false,"auto":"evil\";alert(1);//x"}`, 10, 1},
		{"clean client wipe", `{"dt":false,"auto":""}`, 0, 0},
	}
	for _, tc := range cases {
		score, reasons := shieldProbeSoftScore(tc.probe)
		if score != tc.wantScore || len(reasons) != tc.wantReas {
			t.Fatalf("%s: score=%d reasons=%v, want %d/%d", tc.name, score, reasons, tc.wantScore, tc.wantReas)
		}
	}
}
