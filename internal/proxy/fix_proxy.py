import sys
path = sys.argv[1]
content = open(path).read()

# 1. Add dynamic import
content = content.replace(
    '\t"My-OpenWaf/internal/store"\n)',
    '\t"My-OpenWaf/internal/store"\n\t"My-OpenWaf/internal/waf/dynamic"\n)'
)

# 2. Fix ApplyOutboundForwarding call
content = content.replace(
    'security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, inboundProto(c))',
    'security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, req.URL.Host, inboundProto(c))'
)

# 3. Add dynamic protection logic in ForwardHTTP after copyResponseHeaders
old_forward = '''\tcopyResponseHeaders(c, resp.Header)
\tc.Status(resp.StatusCode)
\t_, err = io.Copy(c.Response.BodyWriter(), resp.Body)
\treturn err
}'''

new_forward = '''\tcopyResponseHeaders(c, resp.Header)

\t// 动态防护处理：根据配置对响应内容进行加密/混淆/水印
\tdp := rt.DynamicProtection
\tif dp.HTMLObfuscationEnabled || dp.JSObfuscationEnabled || dp.ImageWatermarkEnabled {
\t\tct := resp.Header.Get("Content-Type")
\t\tif kind := dynamic.ShouldProcessContentType(ct); kind != "" {
\t\t\tbody, readErr := io.ReadAll(resp.Body)
\t\t\tif readErr != nil {
\t\t\t\treturn readErr
\t\t\t}
\t\t\tprocessor := dynamic.NewProcessor(dp)
\t\t\tprocessed, procErr := processor.Process(requestPath(c), ct, body)
\t\t\tif procErr != nil {
\t\t\t\tprocessed = body
\t\t\t}
\t\t\tc.Status(resp.StatusCode)
\t\t\tc.Response.SetBodyRaw(processed)
\t\t\treturn nil
\t\t}
\t}

\tc.Status(resp.StatusCode)
\t_, err = io.Copy(c.Response.BodyWriter(), resp.Body)
\treturn err
}'''

content = content.replace(old_forward, new_forward)

# 4. Add trimASCIIHeaderSpaceBytes at the end
if 'func trimASCIIHeaderSpaceBytes' not in content:
    content += '''\n// trimASCIIHeaderSpaceBytes trims ASCII space characters from both ends of a byte slice.
func trimASCIIHeaderSpaceBytes(raw []byte) []byte {
\tstart := 0
\tend := len(raw)
\tfor start < end && isASCIISpace(raw[start]) {
\t\tstart++
\t}
\tfor end > start && isASCIISpace(raw[end-1]) {
\t\tend--
\t}
\treturn raw[start:end]
}
'''

open(path, 'w').write(content)
print("Done")
