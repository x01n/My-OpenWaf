/**
 * 威胁情报领域的中文语言包。
 *
 * 与 `zh.ts` 拆分维护：`zh.ts` 通过对象展开合并本文件。
 */

const zhThreatIntel = {
  /* ---------- 页面与 Tab ---------- */
  "threatIntel.title": "威胁情报",
  "threatIntel.description": "订阅外部 IP 黑白名单源，按计划自动同步至本地名单",
  "threatIntel.tabsAria": "威胁情报导航",
  "threatIntel.tab.feeds": "订阅源",
  "threatIntel.tab.logs": "同步日志",
  "threatIntel.create": "新建订阅源",
  "threatIntel.saved": "已保存",
  "threatIntel.saveFailed": "保存失败",

  /* ---------- 枚举：名单类型与动作 ---------- */
  "threatIntel.kind.blacklist": "黑名单",
  "threatIntel.kind.whitelist": "白名单",
  "threatIntel.action.intercept": "拦截",
  "threatIntel.action.drop": "丢弃",

  /* ---------- 同步间隔选项与格式化 ---------- */
  "threatIntel.interval.every5m": "每 5 分钟",
  "threatIntel.interval.every30m": "每 30 分钟",
  "threatIntel.interval.every1h": "每 1 小时",
  "threatIntel.interval.every6h": "每 6 小时",
  "threatIntel.interval.daily": "每天",
  "threatIntel.interval.days": "{count} 天",
  "threatIntel.interval.dayOne": "1 天",
  "threatIntel.interval.hours": "{count} 小时",
  "threatIntel.interval.hourOne": "1 小时",
  "threatIntel.interval.minutes": "{count} 分钟",
  "threatIntel.interval.minuteOne": "1 分钟",
  "threatIntel.interval.seconds": "{count} 秒",
  "threatIntel.interval.secondOne": "1 秒",

  /* ---------- 订阅源列表 ---------- */
  "threatIntel.col.name": "名称",
  "threatIntel.col.url": "URL",
  "threatIntel.col.kind": "类型",
  "threatIntel.col.action": "动作",
  "threatIntel.col.status": "状态",
  "threatIntel.col.syncInterval": "同步间隔",
  "threatIntel.col.entryCount": "条目数",
  "threatIntel.col.lastSync": "上次同步",
  "threatIntel.col.lastError": "最近错误",
  "threatIntel.sync": "同步",
  "threatIntel.syncDone": "同步完成",
  "threatIntel.syncFailed": "同步失败",
  "threatIntel.deleteConfirm": "确认删除订阅源「{name}」？其导入的名单条目将保留",
  "threatIntel.deleted": "已删除",
  "threatIntel.feedsAria": "威胁情报订阅源列表",
  "threatIntel.feedsEmpty": "暂无订阅源",

  /* ---------- 同步日志 ---------- */
  "threatIntel.logs.col.feed": "订阅源",
  "threatIntel.logs.col.startedAt": "开始时间",
  "threatIntel.logs.col.duration": "耗时",
  "threatIntel.logs.col.result": "结果",
  "threatIntel.logs.col.counts": "新增 / 跳过 / 读取行",
  "threatIntel.logs.col.trigger": "触发方式",
  "threatIntel.logs.col.error": "错误",
  "threatIntel.logs.success": "成功",
  "threatIntel.logs.failed": "失败",
  "threatIntel.logs.manual": "手动",
  "threatIntel.logs.scheduled": "定时",
  "threatIntel.logsAria": "同步日志列表",
  "threatIntel.logsEmpty": "暂无同步日志",

  /* ---------- 订阅源表单 ---------- */
  "threatIntel.form.createTitle": "新建订阅源",
  "threatIntel.form.editTitle": "编辑订阅源",
  "threatIntel.form.name": "名称",
  "threatIntel.form.namePlaceholder": "订阅源名称",
  "threatIntel.form.url": "订阅 URL",
  "threatIntel.form.kind": "名单类型",
  "threatIntel.form.action": "命中动作",
  "threatIntel.form.authName": "认证头名称",
  "threatIntel.form.authNamePlaceholder": "认证头名称（可选，如 X-Auth-Key）",
  "threatIntel.form.authValue": "认证头值",
  "threatIntel.form.authValuePlaceholder": "认证头值（可选）",
  "threatIntel.form.syncInterval": "同步间隔",
  "threatIntel.form.site": "绑定站点",
  "threatIntel.form.siteGlobal": "全局（不绑定站点）",
  "threatIntel.form.enabled": "启用订阅",
  "threatIntel.form.required": "请填写名称与订阅 URL",
} as const;

export default zhThreatIntel;
