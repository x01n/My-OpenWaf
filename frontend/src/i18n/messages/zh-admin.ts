/**
 * 账户与密钥领域的中文语言包。
 *
 * 与 `zh.ts` 拆分维护：`zh.ts` 通过对象展开合并本文件。
 */

const zhAdmin = {
  /* ---------- 页面与 Tab ---------- */
  "admin.title": "账户与密钥",
  "admin.description": "管理员账号、API 密钥与会话管理",
  "admin.tabsAria": "账户与密钥",
  "admin.navAria": "账户与密钥导航",
  "admin.tab.users": "管理员账户",
  "admin.tab.apiKeys": "API 密钥",
  "admin.tab.sessions": "登录会话",
  "admin.tab.password": "修改密码",

  /* ---------- 管理员账户：列表 ---------- */
  "admin.users.create": "新建账号",
  "admin.users.listAria": "管理员账号列表",
  "admin.users.empty": "暂无账号",
  "admin.users.col.username": "用户名",
  "admin.users.col.role": "角色",
  "admin.users.col.createdAt": "创建时间",
  "admin.users.changePassword": "改密码",
  "admin.users.changeRole": "改角色",
  "admin.users.deleteConfirm": "确认删除账号 {name}？该账号的会话与 API 密钥将一并失效。",
  "admin.users.created": "已创建账号",
  "admin.users.createFailed": "创建失败",

  /* ---------- 管理员账户：角色枚举 ---------- */
  "admin.users.role": "角色",
  "admin.users.role.admin": "admin（管理员）",
  "admin.users.role.operator": "operator（运维）",
  "admin.users.role.readonly": "readonly（只读）",

  /* ---------- 管理员账户：新建弹窗 ---------- */
  "admin.users.form.createTitle": "新建管理员账号",
  "admin.users.form.createDesc": "密码至少 8 位；保存后立即生效",
  "admin.users.form.submit": "创建",
  "admin.users.form.username": "用户名",
  "admin.users.form.usernamePlaceholder": "用户名（≤64 字符）",
  "admin.users.form.initialPassword": "初始密码",
  "admin.users.form.initialPasswordPlaceholder": "初始密码（至少 8 位）",
  "admin.users.form.newPassword": "新密码",
  "admin.users.form.newPasswordPlaceholder": "新密码（至少 8 位）",

  /* ---------- 管理员账户：改密码 / 改角色弹窗 ---------- */
  "admin.users.passwordDialogTitle": "修改密码",
  "admin.users.passwordDialogDesc": "账号：{name}；保存后该账号需重新登录",
  "admin.users.passwordUpdated": "已更新 {name} 的密码，该账号已有会话已吊销",
  "admin.users.passwordChangeFailed": "修改密码失败",
  "admin.users.roleDialogTitle": "修改角色",
  "admin.users.roleDialogDesc": "账号：{name}",
  "admin.users.roleUpdated": "已更新 {name} 的角色，该账号已有会话已吊销",
  "admin.users.roleChangeFailed": "修改角色失败",

  /* ---------- API 密钥 ---------- */
  "admin.keys.create": "新建 API 密钥",
  "admin.keys.listAria": "API 密钥列表",
  "admin.keys.empty": "暂无 API 密钥",
  "admin.keys.col.name": "名称",
  "admin.keys.col.owner": "所属账号",
  "admin.keys.col.lastUsed": "最近使用",
  "admin.keys.col.createdAt": "创建时间",
  "admin.keys.deleteConfirm": "确认删除 API 密钥「{name}」？使用该密钥的调用将立即失败。",
  "admin.keys.createFailed": "创建失败",
  "admin.keys.form.createTitle": "新建 API 密钥",
  "admin.keys.form.createDesc": "令牌归属于当前登录账号，权限取自账号角色",
  "admin.keys.form.submit": "创建",
  "admin.keys.form.name": "密钥名称",
  "admin.keys.form.namePlaceholder": "例如：ci-runner",
  "admin.keys.createdTitle": "API 密钥已创建",
  "admin.keys.ackSaved": "我已保存",
  "admin.keys.revealWarning": "令牌仅显示一次，关闭后无法再次查看。请立即复制并妥善保存。",
  "admin.keys.copy": "复制",
  "admin.keys.copied": "已复制",
  "admin.keys.copiedToast": "已复制到剪贴板",
  "admin.keys.copyFailed": "复制失败",
  "admin.keys.copyFailedDesc": "浏览器未授予剪贴板权限，请手动选中复制",
  "admin.keys.usageHint": "在请求头使用 Authorization: Bearer <token>",

  /* ---------- 登录会话 ---------- */
  "admin.sessions.activeCount": "共 {count} 个活跃会话",
  "admin.sessions.listAria": "登录会话列表",
  "admin.sessions.empty": "暂无活跃会话",
  "admin.sessions.col.username": "账号",
  "admin.sessions.col.ip": "IP",
  "admin.sessions.col.device": "设备 / 客户端",
  "admin.sessions.col.loginAt": "登录时间",
  "admin.sessions.col.lastActiveAt": "最后活跃",
  "admin.sessions.col.expiresAt": "过期时间",
  "admin.sessions.revoke": "强制下线",
  "admin.sessions.revokeConfirm": "确认强制下线账号 {name} 的该会话？其访问令牌与刷新令牌会一并吊销。",
  "admin.sessions.revoked": "已强制下线",

  /* ---------- 修改自己的密码 ---------- */
  "admin.account.title": "修改当前账号密码",
  "admin.account.desc": "修改成功后所有旧凭据失效，需要重新登录",
  "admin.account.warning": "新密码至少 8 位；修改成功后当前会话会立即失效。",
  "admin.account.currentPassword": "当前密码",
  "admin.account.newPassword": "新密码",
  "admin.account.minChars": "至少 8 位",
  "admin.account.confirmPassword": "确认新密码",
  "admin.account.mismatch": "两次输入的新密码不一致",
  "admin.account.changePassword": "修改密码",
  "admin.account.changedRelogin": "密码已修改，请重新登录",
  "admin.account.changeFailed": "修改失败",
} as const;

export default zhAdmin;
