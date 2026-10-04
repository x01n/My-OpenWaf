package app

import (
	"fmt"

	"My-OpenWaf/internal/waf/jsplugin"
)

/**
 * ensureJSPluginEngine 在首次需要时创建进程级 QuickJS 执行器。
 *
 * 脚本代次为空时绝不关闭现有执行器：已经捕获了旧快照的请求仍要执行其中的脚本，
 * 提前销毁会让这些请求失去脚本能力。
 *
 * @param current 当前已持有的执行器。
 * @param scripts 本次快照编译出的脚本集合。
 * @return 可用的执行器。
 */
func ensureJSPluginEngine(current *jsplugin.Engine, scripts []*jsplugin.Script) (*jsplugin.Engine, error) {
	if len(scripts) == 0 || current != nil {
		return current, nil
	}
	created, err := jsplugin.NewEngine(jsplugin.EngineOptions{})
	if err != nil {
		return nil, fmt.Errorf("create js plugin engine: %w", err)
	}
	return created, nil
}

/**
 * ensureJSPluginEngineForDryRun 为管理端 dry-run 端点惰性创建进程级执行器，
 * 即使当前快照里没有任何启用的脚本也要能跑。
 *
 * 调用方必须把创建过程与 reload、shutdown 串行化，否则会与热替换竞争。
 *
 * @param current 当前已持有的执行器。
 * @return 可用的 JS 插件执行器。
 */
func ensureJSPluginEngineForDryRun(current *jsplugin.Engine) (*jsplugin.Engine, error) {
	if current != nil {
		return current, nil
	}
	created, err := jsplugin.NewEngine(jsplugin.EngineOptions{})
	if err != nil {
		return nil, fmt.Errorf("create js plugin engine for dry-run: %w", err)
	}
	return created, nil
}
