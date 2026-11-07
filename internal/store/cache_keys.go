package store

// AccessLogRequestCacheKey 返回按 request_id 索引访问日志详情的缓存键
// （不含 cache 包的全局前缀，调用方需配合 cache.HotKey 使用）。
func AccessLogRequestCacheKey(requestID string) string {
	return "al_req:" + requestID
}

// SecurityEventRequestCacheKey 返回按 request_id 索引安全事件列表的缓存键
// （不含 cache 包的全局前缀）。
//
// 与访问日志不同，一个 request_id 可能对应多条安全事件，因此缓存值是数组；
// 写侧在事务提交后删除该键，让下一次读回源数据库取到完整集合。
func SecurityEventRequestCacheKey(requestID string) string {
	return "se_req:" + requestID
}
