package dataplane

import (
	"testing"
)

/**
 * TestAuditAccessLogSamplingIsAConsumer 证明 MY_OPENWAF_ACCESSLOG_SAMPLING 有一条
 * 真正的生产消费点：recordAccessLog 里的 shouldRecordAccessLog 闸门
 * （internal/dataplane/access_log.go:513）。
 *
 * 判据设计：采样分母只影响「普通成功请求」是否落库；带 WAF 动作、4xx/5xx 与
 * ForceRecord 的记录不受采样影响。因此若 rate 不是消费点，rate=0 与 rate=1
 * 的行为必然相同——两者不同即证明该字段改变了请求处理结果。
 */
func TestAuditAccessLogSamplingIsAConsumer(t *testing.T) {
	ordinary := accessLogInfo{WAFAction: "none", StatusCode: 200}

	// rate=0：普通成功请求全部不落库（该档在生产不会出现，此处只作为「字段真的被读」的判据）。
	if shouldRecordAccessLog(ordinary, 0) {
		t.Error("rate=0 时普通成功请求仍被记录：采样分母未参与判定")
	}
	// rate=1：全量记录。
	if !shouldRecordAccessLog(ordinary, 1) {
		t.Error("rate=1 时普通成功请求未被记录：全量语义被破坏")
	}
	// rate=0 的例外路径仍须留档。
	for _, info := range []accessLogInfo{
		{WAFAction: "intercept", StatusCode: 403},
		{WAFAction: "none", StatusCode: 500},
		{WAFAction: "observe", StatusCode: 200},
		{WAFAction: "none", StatusCode: 200, ForceRecord: true},
	} {
		if !shouldRecordAccessLog(info, 0) {
			t.Errorf("rate=0 时例外路径被丢弃：%+v", info)
		}
	}
}

/**
 * TestAuditAccessLogSamplingRateN 钉住 rate>1 时的取模采样确实发生。
 *
 * 直接读包内计数器推期望值，避免「按实现重写一遍」的同义反复：期望条数由
 * counter 的初值与末值决定，与实际实现使用的模运算无关的计数方式给出。
 */
func TestAuditAccessLogSamplingRateN(t *testing.T) {
	const rate = 4
	ordinary := accessLogInfo{WAFAction: "none", StatusCode: 200}

	before := accessLogSampleCounter.Load()
	recorded := 0
	for i := 0; i < 40; i++ {
		if shouldRecordAccessLog(ordinary, rate) {
			recorded++
		}
	}
	after := accessLogSampleCounter.Load()
	want := int(after/rate) - int(before/rate)
	if recorded != want {
		t.Fatalf("rate=%d 时 40 次判定记录 %d 条，期望 %d 条（counter %d→%d）", rate, recorded, want, before, after)
	}
	if recorded == 0 || recorded == 40 {
		t.Fatalf("rate=%d 未产生采样效果：记录 %d/40 条", rate, recorded)
	}
}
