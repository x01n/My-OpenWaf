package proxy

import (
	"bytes"
	"io"
)

/**
 * DecodeRequestBodyBytesForInspection 为 WAF 采样解码一段压缩请求体字节。
 *
 * 与转发路径的解码（decodeUpstreamRequestBody*）刻意分开：转发必须解出完整
 * 明文，采样只需要够填满 WAF 扫描窗的前缀，且必须能提前停止。两者共用同一
 * 套解码器构造，编码支持集与 deflate 探测回退不会出现第二份实现。
 *
 * 调用方传进来的必须是一段已在内存里的完整字节（数据面传的是请求体偷读
 * 前缀）：本函数不读网络，因此不会让请求在等待更多请求体时挂住，也不会
 * 把上游的上传节奏提前拉走。
 *
 * 压缩体被截断是常态而非异常：偷读前缀常常只是完整压缩体的一段，此时末端
 * 的读取错误只表示「样本不完整」。已解出的明文照常返回，调用方送检时把它
 * 当上限截断处理，绝不可据此判请求失败。
 *
 * @param body 原始请求体字节或其在内存中的前缀（压缩态）。
 * @param contentEncoding Content-Encoding 头的原始取值。
 * @param maxDecodedBytes 明文产出上限；超出部分丢弃。
 * @returns decoded 明文（压缩体不完整时为失败前已解出的部分）；didDecode 是否
 *          识别并应用了内容编码，为 false 时 decoded 等于 body 且调用方应
 *          回退到未压缩路径；truncated 样本是否不完整（被上限截断、压缩体到
 *          此为止，或压缩炸弹上限中断了解压）。
 */
func DecodeRequestBodyBytesForInspection(body []byte, contentEncoding []byte, maxDecodedBytes int) ([]byte, bool, bool) {
	sample := DecodeRequestBodyInspectionSample(body, contentEncoding, maxDecodedBytes)
	return sample.Decoded, sample.DidDecode, sample.Truncated
}

/**
 * RequestBodyInspectionSample 是一次采样解码的完整结果。
 *
 * 三个布尔位描述三种互不相同、处置也不同的情形：
 *
 *   - Truncated：样本不完整，但已解出的明文字节可信（分块吐数据的 gzip/br/
 *     deflate 在前缀被截断时属于这一类）。照常送检。
 *   - Undecodable：编码受支持、却一个字节都没解出来（zstd 的帧结构要求读到
 *     帧尾，前缀被截断时产出恒为空）。样本为空意味着「没东西可检」，调用方
 *     应走降级：不解压、不拒绝、按原始压缩字节转发，并记事件。
 *   - LimitExceeded：解压产出触及压缩炸弹上限，解压已中断。
 */
type RequestBodyInspectionSample struct {
	Decoded       []byte
	DidDecode     bool
	Truncated     bool
	Undecodable   bool
	LimitExceeded bool
}

/**
 * DecodeRequestBodyInspectionSample 是采样解码的完整形态。
 *
 * 与 DecodeRequestBodyBytesForInspection 的差别只在返回值粒度：那一个版本
 * 保留给只需要「样本 + 是否解压 + 是否截断」的调用方，本函数供数据面区分
 * 「样本不完整」与「样本为空」——后者的处置是降级放行，不是照常送检。
 *
 * @param body 原始请求体字节或其在内存中的前缀（压缩态）。
 * @param contentEncoding Content-Encoding 头的原始取值。
 * @param maxDecodedBytes 明文产出上限；超出部分丢弃。
 * @returns 采样结果，见 RequestBodyInspectionSample。
 */
func DecodeRequestBodyInspectionSample(body []byte, contentEncoding []byte, maxDecodedBytes int) RequestBodyInspectionSample {
	if len(body) == 0 || len(contentEncoding) == 0 {
		return RequestBodyInspectionSample{Decoded: body}
	}
	// 炸弹中断必须在上限触发点捕获：产出上限是用 io.LimitReader(max+1) 表达的，
	// 读满即返回 EOF，守卫抛出的 errDecompressionLimitExceeded 会被 LimitReader
	// 的 EOF 盖掉，回调是唯一可靠的信号。
	var limitErr error
	reader, didDecode, err := decodeUpstreamRequestBodyStreamBytesWithTrip(bytes.NewReader(body), contentEncoding, func() {
		limitErr = errDecompressionLimitExceeded
	})
	if err != nil || !didDecode || reader == nil {
		// 解码器构造失败（声明受支持编码但字节流不是该编码）：样本回退成原始
		// 字节，由调用方按未压缩路径处理，与改动前一致。
		return RequestBodyInspectionSample{Decoded: body}
	}
	if maxDecodedBytes < 0 {
		maxDecodedBytes = 0
	}

	// 产出上限用 io.LimitReader(reader, max+1) 表达，与响应侧
	// readUpstreamResponseBodyLimitedInternal 同构；多出的那一个字节只用来
	// 判定截断，不会外泄给调用方。
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(maxDecodedBytes)+1))
	_ = reader.Close()

	sample := RequestBodyInspectionSample{
		Decoded:       decoded,
		DidDecode:     true,
		Truncated:     readErr != nil,
		LimitExceeded: limitErr != nil,
	}
	if len(decoded) > maxDecodedBytes {
		sample.Decoded = decoded[:maxDecodedBytes]
		sample.Truncated = true
	}
	// 一个字节都没解出来，且读取没有干净结束：前缀不足以让解码器吐出任何
	// 内容（zstd 的典型形态）。这时样本本身没有检测价值，标记为不可解码。
	sample.Undecodable = len(sample.Decoded) == 0 && readErr != nil
	return sample
}
