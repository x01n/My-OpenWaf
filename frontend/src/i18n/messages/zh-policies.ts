/**
 * 策略领域的中文语言包。
 *
 * 与 `zh.ts` 拆分维护：`zh.ts` 通过对象展开合并本文件。
 */

const zhPolicies = {
  /* ---------- 页面与列表 ---------- */
  "policies.title": "策略管理",
  "policies.description": "规则策略是自定义规则的容器，站点通过绑定策略获得防护配置",
  "policies.create": "新建策略",
  "policies.listAria": "策略列表",
  "policies.empty": "暂无策略",
  "policies.col.name": "名称",
  "policies.col.description": "描述",
  "policies.col.isDefault": "是否默认",
  "policies.col.createdAt": "创建时间",
  "policies.defaultBadge": "默认",
  "policies.yes": "是",
  "policies.no": "否",

  /* ---------- 行内操作 ---------- */
  "policies.owaspSummary": "OWASP 概要",
  "policies.setDefault": "设为默认",
  "policies.setDefaultConfirm": "确认将「{name}」设为默认策略？未绑定策略的站点将立即使用该策略。",
  "policies.setDefaultSuccess": "已设为默认",
  "policies.deleteConfirm": "确认删除策略「{name}」？被站点引用的策略将删除失败。",
  "policies.deleteSuccess": "已删除",

  /* ---------- 新建 / 编辑表单 ---------- */
  "policies.form.createTitle": "新建策略",
  "policies.form.editTitle": "编辑策略 #{id}",
  "policies.form.name": "策略名称",
  "policies.form.namePlaceholder": "策略名称（必填）",
  "policies.form.description": "策略描述",
  "policies.form.descriptionPlaceholder": "策略描述（可选）",
  "policies.error.name": "请填写策略名称",
  "policies.saveFailed": "保存失败",
  "policies.saved": "已保存",

  /* ---------- 详情抽屉 ---------- */
  "policies.detail.title": "策略详情",
  "policies.detail.subtitle": "策略 #{id}",
  "policies.field.description": "描述",
  "policies.field.isDefault": "默认策略",
  "policies.field.createdAt": "创建时间",
  "policies.field.updatedAt": "更新时间",

  /* ---------- OWASP 概要 ---------- */
  "policies.owasp.title": "OWASP 规则概要",
  "policies.owasp.total": "规则总数",
  "policies.owasp.enabled": "已启用",
  "policies.owasp.disabled": "已停用",
  "policies.owasp.empty": "该策略未启用任何 OWASP 分类",
} as const;

export default zhPolicies;
