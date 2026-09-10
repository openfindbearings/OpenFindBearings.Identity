# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.12.0
**日期：** 2026-09-10
**状态：** 现状与代码同步（v2.11.0 的 P1 清单已基本落地，本版如实记录；剩余待实施项标注）

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 ~ v2.10.0 | 2026-05 ~ 09 | 见历史版本文件（用户/角色/租户隔离/OIDC 端点/SMS grant/设备绑定/客户端命名统一等） |
| v2.11.0 | 2026-09-08 | 移动端登录与商户入驻设计评审结论纳入；提出 P1 安全完善清单 S1-S9 |
| v2.12.0 | 2026-09-10 | ① access 寿命定案 **10 分钟**（曾拟改 5 分钟，实测权衡后维持 10，撤销全文 5 分钟表述）；② S1 账户锁定/S2 刷新查状态/S3 令牌吊销/S5 DP 持久化/S6 revocation 权限/S7 寿命 按已实现记录，S4 改部分完成，S8 更新进度；③ §5.2 受众编辑、§5.3 客户端管理修复按落地情况更新（CreateAsync 参数化仍待做）；④ §9 管理端点角色门禁已补齐；⑤ §10.2 Sync 令牌缓存改比例缓冲描述；⑥ §4 补 OpenIddict 双表合并（Oidc* Guid 键单套实体）；⑦ §8 新增 S10 注册用户默认角色（待拍板）；⑧ §12 专项清单同步现状 |

---

## 1. 项目定位

OpenFindBearings.Identity 是全局 OIDC 认证中心，一个进程承载两套独立系统：

| | 自管理后台 | OIDC 认证服务 |
|---|---|---|
| 用途 | 管理用户/租户/客户端/Scope | 为 Admin/App/Sync 提供 OAuth/OIDC 认证 |
| 入口 | 直接访问站点 | 被 OAuth authorize 重定向 |
| 认证 | Cookie `Identity.Application`（自管理用 token 里的 role） | OpenIddict 服务端 |
| 用户池 | 同一用户池，按 `TenantId` 区分 | 同左 |

**职责边界**：
- Identity 只负责"认证 + 签发令牌 + 租户隔离 + 用户主体 CRUD"。
- **不负责业务 RBAC**：OpenFindBearings 各业务系统的细粒度权限由各自查库判定（见 §10.5 重要约定：业务鉴权不信 JWT 的 role claim）。
- 认证事实源在 Identity；业务事实源在 API；**单向同步**（API 不反写 Identity，Identity 不查 API）。

---

## 2. 租户隔离体系

### 2.1 租户解析
后端同时支持两种标识，两者皆空则拒绝（400）：
1. `realm=租户名称`（推荐，各接入系统默认）→ 查 Tenants 表按 Name 匹配。
2. `tenant_id=GUID`（优先级高于 realm）→ 按 Id 匹配。

`TenantContextMiddleware` 在管道最前端（`UseAuthentication` 前）解析并缓存到 `HttpContext.Items["TenantInfo"]`，后续 `ITenantResolver.ResolveAsync()` 读缓存。

### 2.2 隔离层级
| 资源 | 隔离方式 | 字段 |
|------|---------|------|
| 用户 OidcUser | 完整隔离 | TenantId (Guid?) |
| 客户端 OidcApplication | 完整隔离 | TenantId (Guid?) |
| Scope OidcScope | 完整隔离 | TenantId (Guid?) |
| 角色 IdentityRole | 影子属性 | TenantId (shadow) |
| 授权 OidcAuthorization | 完整隔离 | TenantId (Guid?) |
| 令牌 OidcToken | 经授权链隔离 | 无直接字段 |

### 2.3 管理 UI 租户过滤
- 系统管理员（TenantId=SystemTenantId）：看所有租户。
- 非系统管理员（TenantId=OpenFindBearingsTenantId）：仅看本租户。

---

## 3. Cookie 认证方案（自管理）

单 cookie 方案 `Identity.Application`，登录走 `SignInManager.SignInAsync()`，隔离靠代码级 TenantId 判断。所有 OIDC 端点（authorize/token/userinfo/logout）均做租户校验（client_id/scope/用户 TenantId 三重）；`connect/revocation` 由 OpenIddict 内部处理、免租户校验。

---

## 4. OpenIddict 自定义实体与表布局

为在 OpenIddict 实体加 TenantId，定义 4 个继承类：OidcApplication、OidcAuthorization、OidcScope、OidcToken（无 TenantId、经授权链隔离）。GUID 主键（`ReplaceDefaultEntities<...Guid>`），表名显式映射：

| 实体 | 表 |
|---|---|
| OidcApplication | `OidcApplications` |
| OidcAuthorization | `OidcAuthorizations` |
| OidcScope | `OidcScopes` |
| OidcToken | `OidcTokens` |

**双表合并（v2.12.0 落地）**：历史上 `options.UseOpenIddict()` 与自定义实体并存，导致库里多出一套 0 行的默认 string 键 `OpenIddict*` 壳表（真数据一直在 `Oidc*`）。已删除该行注册，并应用迁移 `ConsolidateOpenIddictTablesDropDefaults` drop 掉 4 张壳表；服务层读写与仪表盘计数统一走 `OpenIddictEntityFrameworkCoreApplication/Scope<Guid>` 等 Guid 键实体。`Oidc` 前缀保留：与 ASP.NET Identity 表族并存的命名习惯，裸名 Tokens/Scopes 语义过泛（易与 UserTokens、业务 scope 混淆），去前缀需再做一次 RenameTable 迁移，收益不成比例。

---

## 5. 客户端注册表（现状，源自 SeedData）

| ClientId | 类型 | 显示名 | 授权类型 | 端点/关键权限 | Scope | 重定向 |
|---|---|---|---|---|---|---|
| `sync-client` | 机密（有 secret） | 同步服务客户端 | client_credentials、refresh_token | Token | api:sync | 无（M2M） |
| `mobile-client` | **公开**（无 secret） | 移动端 Taro | password、sms（custom）、refresh_token | Token、**Revocation** | api:mobile | 无（直连 token） |
| `web-client` | 机密 | WEB 客户端（预留外部） | authorization_code、refresh_token | Authorization、Token、EndSession、Code、**PKCE 必需** | api:web | localhost:5002/signin-oidc |
| `admin_client` | 机密 | Admin 后台管理 | authorization_code、refresh_token | Authorization、Token、EndSession、Code；ConsentType=Implicit | openid、api:admin、api:mobile、**offline_access** | admin.515813.xyz/callback、/signout-callback-oidc |

> 已落地：`mobile-client` 已补 `Permissions.Endpoints.Revocation`；`admin_client` 已补 `scp:offline_access`（授权码流程签发 refresh_token 的前提，Admin 无感续期的根修）。两处均配 SeedData 幂等补丁 `EnsureClientPermissionsAsync`（CreateIfNotExists 只建不改 → 对已存在客户端**只追加缺失权限、不覆盖既有字段**），老库发布新镜像即自愈，免手工 SQL。
> [待实施 P1] SeedData 内 client secret（`SeedData.cs:459/497/523`）仍为明文常量，须移出源码、改 K8s Secret 注入（证书密码部分已完成，见 §8 S4）。

### 5.1 Scope 与资源（aud）模型
| Scope | 关联资源（token 的 aud） |
|-------|------|
| api:sync | openfindbearings-api |
| api:admin | openfindbearings-api、openfindbearings-sync |
| api:mobile | openfindbearings-api |
| api:web | openfindbearings-api |

每个后台微服务有独立资源标识；`api:admin` 关联全部服务资源，Admin token 携多 aud 可统一访问后台微服务。新增服务时在 `ApiResourceConstants` 加常量并追加到 `api:admin` 资源列表。

### 5.2 受众（资源/aud）的维护
- **模型**：OpenIddict 的 Scope 带 `Resources` 集合 = 该 scope 签发 token 的 `aud` 值；受众即后台微服务资源标识。
- **现状（v2.12.0 更新）**：受众已可在 Scope 管理 UI 编辑——`ScopeService.UpdateAsync` 支持整体替换/保留 Resources（不传即不动），表单提供受众文本域。资源↔scope 的**初始**映射仍在 SeedData（`ApiResourceConstants`）。
- **新增服务步骤**：`ApiResourceConstants` 加常量 → 在 Scope 管理页把资源追加到相关 scope（通常 api:admin）的受众 → 各服务 `ValidAudiences` 同步。

### 5.3 客户端/Scope 管理的修复状态
- **已修复（v2.12.0 落地）**：
  - `ClientService.UpdateAsync` 改为**直改实体列**（DisplayName/ClientType/ConsentType/RedirectUris/PostLogout/Permissions(JSON) 按字段更新），不再重放 descriptor → 保存不抹未编辑字段、不触发 confidential 客户端 secret 校验（改名即失效的原 bug 根修）。
  - `RegenerateSecretAsync` 改"读-改-写全量 descriptor"，先取回全部字段再只换 secret。
  - 编辑 UI Keycloak 式补全：访问类型/同意要求下拉、回调与登出回调每行一个、AllowedScopes 复选框（写 `scp:*` 权限、保留 ept 等其它前缀）；ClientId/Permissions 原值只读展示。
  - 表单分发统一：Application/Scope/Users/Role/Tenant 控制器全部走 service，不直连 DbContext/manager；`Edit` 表单补齐路由参数（原漏 `asp-route-*` 导致 POST 静默 Forbid，"保存无反应"根因之一）。
  - Role CRUD 补全（`RoleService.UpdateAsync` 重命名 + RoleController + 三视图）；用户编辑页补全（资料字段 + 角色勾选整体替换 `SetRolesAsync`）。
- **仍待做 [待实施 P2]**：
  - `ClientService.CreateAsync` 仍硬编码 authorization_code 系权限集 + 单 RedirectUri，无法直接创建公开客户端（password/sms 型）→ 需参数化（按 ClientType + 授权类型集合构建 descriptor）。

---

## 6. 授权类型与端点

### 6.1 服务端启用的 grant（ServiceExtensions）
`client_credentials`、`password`、`sms`（custom）、`authorization_code`、`refresh_token`。
`wechat`、`alipay` 为注释占位（`HandleWeChatAsync` 等是 NotImplementedException stub）——[待实施 P5+] 微信一键登录需企业认证 + 手机号授权资质，预留常量已存在（GrantTypeConstants.WeChat 等），届时启用。

### 6.2 OAuth/OIDC 端点
| 端点 | 用途 | 租户校验 |
|------|------|---------|
| `/connect/authorize` | 授权码流程入口（Admin/web），支持 `device_id` 参数写入授权码 principal | 是 |
| `/connect/token` | 换/刷令牌（所有 grant） | 是 |
| `/connect/userinfo` | 用户信息 | 是 |
| `/connect/logout` | RP-Initiated Logout（浏览器 SSO 结束会话，需 end_session 权限），post_logout_redirect 精确匹配校验 | 是 |
| `/connect/revocation` | 令牌吊销（移动端登出用，需 revocation 权限） | OpenIddict 内部 |

**认证端点限流（v2.12.0 新增落地）**：`/connect/*`、`/api/account/signup`、`/api/sms/send-code` 按客户端 IP 固定窗口 30 次/分钟，超限 429（`Program.cs` GlobalLimiter，位于 `UseForwardedHeaders` 之后取真实 IP）；其余路径不限流。与账号锁定构成"每账号 + 每 IP"两层暴力破解防护。

### 6.3 SMS 验证码
- `POST /api/sms/send-code`（匿名，含 SmsCodeType）。
- `grant_type=sms`：手机号 + 验证码校验通过即签发令牌；**首次使用自动建无密码 OIDC 用户**（登录即注册）。
- **现状（v2.12.0 更新）**：开发模式经配置切换——`Sms:DevMode=true` 时用固定码 `Sms:DevFixedCode`（默认 123456）落库并记日志；**默认（生产）关闭**，走随机码。同号码同类型发送频控已有（`CanSendAsync`）。验证码 5 分钟有效。
- [待实施 P2] 接真实短信通道；`SignUp` 密码改可选以支持免密注册。

---

## 7. 令牌生命周期与会话策略

### 7.1 寿命（定案）
| 令牌 | 寿命 | 说明 |
|---|---|---|
| access | **10 分钟（定案）** | 曾评估缩短为 5 分钟以减小吊销窗口，权衡后**维持 10 分钟**（10 分钟体感不长、降低刷新/重取频率；吊销窗口 ≤10 分钟已接受）。全局唯一配置点 `ServiceExtensions.SetAccessTokenLifetime`，全链路消费方均按响应 `expires_in` 自适应，无硬编码。 |
| refresh | 30 天 | 绝对有效期 |
| authorization_code | 默认 | 一次性 |

### 7.2 滚动轮换（澄清）
**refresh 滚动轮换是 OpenIddict 默认行为、已生效**（未调用 `DisableRollingRefreshTokens`）：每次刷新旧 refresh 标记 redeemed、响应返回新 refresh，并带 30 秒重用宽限（reuse leeway）。**无需任何配置**。因此客户端"刷新 single-flight"是纵深防御（非硬性必需）。

### 7.3 device_id 设备绑定（现状）
- 登录（password/sms）读 `device_id` 写入 JWT claim；授权码流程（authorize 查询串）写入授权码 principal；刷新时比对，**原 token 带而请求不带或不一致 → invalid_grant**；原 token 不带则跳过（旧客户端兼容）。刷新成功的新令牌续传原 device_id claim。
- 语义：**防 refresh token 被复制到其它设备盗用**（刷新即时拒），**不是**单设备互踢。
- device_id 为客户端自报、服务端只做一致性比对——防误用/串设备，**不防伪造**（隐私文案不得承诺"防盗号"）。

### 7.4 单设备互踢（已实现，按 client 隔离）
- 目标：同账号在同一客户端只允许一个会话在线，新登录踢旧（微信式），**按 client 隔离**——不影响 Admin 网页 / Sync M2M。
- 机制：password/sms grant 登录成功、签发新令牌**之前**，`TokenRevocationService.RevokeRefreshTokensForClientAsync(subject, clientId)` 吊销该 subject 在**该 client** 下的既有 refresh token（AuthorizationController，password grant 与 sms grant 两处）。当前实际走 password/sms 的只有 mobile-client，等效"限移动端"；sync-client 是 client_credentials 不经过此路径。
- 生效时延：旧设备手里 access token（≤10 分钟）过期后刷新被拒 → 掉线回登录页。**非秒踢**（无推送通道；秒踢需 reference token + introspection，不做）。
- 与 device_id 关系：互补——互踢管"同账号一台设备在线"，device_id 管"token 不被异机盗用"。两者都保留。

### 7.5 令牌吊销（已实现）
- 触发点与入口（全部收敛到 `ITokenRevocationService`，内部按 subject(+application) 查 refresh 令牌经 EF 置 revoked，编程调用、不改 grant/端点/handler/租户模型）：
  | 触发 | 入口 | 吊销范围 |
  |---|---|---|
  | 用户自助改密 | 管理台 `ProfileController.ChangePassword` / API `me/change-password` → `UserService.ResetPasswordAsync` | 全部 client |
  | 管理员重置密码 | `UserService.ResetPasswordAsync` | 全部 client |
  | 禁用用户 | `UserService.DisableAsync` | 全部 client |
  | 注销/删除账户 | `UserService.DeleteAsync` | 全部 client |
  | 移动端登出 | 客户端调 `/connect/revocation`（refresh_token，mobile-client 已具 revocation 权限） | 该令牌 |
- 刷新链路兜底：refresh grant 处理中先 `CheckCanLoginAsync`（禁用/锁定/删除的用户即便持有未吊销 refresh 也拒绝续期）。
- 残余窗口：access token（10 分钟）不可吊销，吊销/登出后最长 10 分钟内旧 access 仍可用（行业常规）。`/connect/logout` 是浏览器 SSO 会话结束，对无 cookie 的移动端无意义。

---

## 8. 安全完善清单（S 表，v2.12.0 状态更新）

| # | 项 | 状态 | 现状说明 | 阶段 |
|---|---|---|---|---|
| S1 | 账户锁定 + 端点限流 | 已完成 | 域内锁定：`OidcUser.RecordFailedLogin`（5 次失败锁 15 分钟，grant 失败路径计数、`IsAvailable` 判定拒绝）+ 认证端点 IP 限流 30/分钟（§6.2）。`IdentityOptions.Lockout` 三行注释保留（不走 SignInManager 锁定机制，不依赖）。 | P1 |
| S2 | 刷新查用户状态 | 已完成 | `HandleRefreshTokenAsync` 已调 `CheckCanLoginAsync`。 | P1 |
| S3 | 令牌吊销 | 已完成 | 见 §7.5（TokenRevocationService + UserService 四触发点 + 登出 revocation）。 | P1 |
| S4 | 机密出源码 | **部分** | 已完成：生产证书密码去默认值，缺失配置快速失败（K8s Secret 注入）。未完成：SeedData 三个 client secret 仍明文常量（:459/:497/:523）。 | P1 |
| S5 | Data Protection 持久化 | 已完成 | `Program.cs` 按 `DataProtection:KeysPath` 启用；K3s 配 hostPath `/app/dpkeys`（单副本）。Pod 重启后 OIDC 关联 state/认证 cookie 不再失效。 | P1 |
| S6 | mobile-client revocation 权限 | 已完成 | SeedData 新库直配 + 老库 `EnsureClientPermissionsAsync` 幂等补丁（admin_client offline_access 同机制）。 | P1 |
| S7 | access 寿命 | 已完成 | **定案 10 分钟**（不再改 5）。 | P1 |
| S8 | SMS 真实发送 + 免密注册 | 部分 | 已做：DevMode 配置化（生产默认随机码）+ 发送频控。未做：真实短信通道、SignUp 密码可选。 | P2 |
| S9 | 服务间用户查询 | 未动 | API 依赖的 `/api/users/by-phone` 等仍不存在（邀请链路待落地）；方案不变：API 持 M2M token 调 `/api/account/admin/users` 或 Identity 补服务间端点。 | P2/P4 |
| S10 | 注册用户默认角色（新增） | 待拍板 | `signup` → `UserService.CreateAsync` 不分配任何 Identity 角色。现状不影响 Taro 用：业务 API JIT 补 `Individual`、`/api/me` 仅要求已认证。决策点：是否在 Identity 侧给注册账号默认加 `User` 角色（为 Identity 侧"登录准入类"策略预留抓手）；若做，需配存量用户补角色幂等补丁。 | 待定 |

---

## 9. API 端点（AccountController / SmsController / AuditLog / SystemConfig）

（与 v2.10.0 一致，摘要）
- `/api/account/signup`（匿名，注册，请求体 SignUpRequest{account,password,confirmPassword,agreeTerms,realm,inviteCode?}，**只返回 UserResponse 不返回 token**；account 可为用户名/邮箱/手机号）
- `/api/account/me`、`/me/profile`、`/me/change-password`、`/me/account`(软删)（OpenIddict Bearer）
- `/api/account/admin/users` CRUD + `/permanent`(物理删，仅已软删) + `/status` + `/unlock` + `/reset-password` + `/restore`（Bearer + SuperAdmin/Admin）
- `/api/sms/send-code`（匿名）
- `/api/auditlog/*`、`/api/systemconfig/*`（Bearer + SuperAdmin/Admin）

> 已修复（v2.12.0 落地）：管理控制器角色门禁补齐——MVC 侧 UsersController/TenantController/ApplicationController/ScopeController/RoleController 均 `[Authorize(Roles = "SuperAdmin,Admin")]`；API 侧管理端点维持 Bearer + 角色门禁。"任意登录用户可访问管理端点"的缺口关闭。

---

## 10. 各端对接指南

### 10.1 Admin 后台（admin_client，authorization_code）
- 流程：浏览器重定向 `/connect/authorize`（带 realm、scope=`openid profile roles api:admin api:mobile offline_access`）→ 登录 → code 回 `/callback` → 换 token（**Basic 头单凭证，表单不再带 client_secret**，ID2087 根修）。
- 现状：手写 OIDC RP，token 存 HttpOnly cookie claims；对下游 API/Sync 的取用统一经 `AdminTokenService`（**按 device_id 分键的进程内缓存 + 单飞锁**，多浏览器不互踩、并发 401 不踩踏），`BearerTokenHandler` 在 401 时触发强制刷新（刷新失败保留现有 access）。offline_access 补齐后 cookie 内有 refresh_token，access 过期可无感续期（此前"登录 10 分钟后全站 401 跳不出"已根修）。
- device_id：Admin 生成随机 Guid 存 HttpOnly cookie，附 authorize URL 与 token/refresh 请求。
- 已知债（另立专项）：state 生成后未校验（登录 CSRF）、回调 JWT 只 Base64 解不验签、`state=="changepwd"` hack。**刷新竞态一项已由单飞锁解决**。标准化为 AddOpenIdConnect 可一并收口，但标准 handler 内部刷新带不了自定义 device_id → 须先决定"放弃 device_id 或子类化 handler"。见 §12.1。
- 单设备互踢**不影响** Admin（授权码流不经 password/sms 的按 client 吊销路径）。

### 10.2 Sync 服务（sync-client，client_credentials）
- M2M：`/connect/token` 用 client_credentials + scope=api:sync 取 token（aud=openfindbearings-api），进程级缓存。
- **缓存策略（v2.12.0 更新）**：按响应 `expires_in` 比例留缓冲——`buffer = max(30s, expiresIn × 20%)`，access 10 分钟 → 缓存约 8 分钟；access 寿命再调整自适应，无需改码（`BusinessApiClient`）。
- 无 refresh token 交互、无 device_id、无用户上下文。
- Sync 自身 API 的 ValidAudiences 含 [openfindbearings-sync, openfindbearings-api, api:sync]。

### 10.3 移动端（mobile-client，password/sms，经 BFF）
- **Taro 不直连 Identity**，统一经 BFF（OpenFindBearings.Mobile）：
  - 注册 `POST /mobile/auth/register` → BFF 链式调 Identity `signup` + `password` grant，返回 token（错误码映射 USER_EXISTS=409 等）。
  - 登录 `POST /mobile/auth/login`（username/password/deviceId）、`/login-sms`（phone/code/deviceId）、发码 `/send-code`、刷新 `/refresh`（透传 device_id）。
- BFF→Identity 的 `/connect/token` 必须带 `client_id=mobile-client`、`realm=openfindbearings`、`scope=api:mobile`（否则租户关拒绝 / token 无 aud / API 401）。
- BFF `Identity:Audience` 须为资源名 `openfindbearings-api`（非 api:mobile）。
- 令牌策略（Taro 侧）：access 仅内存、refresh 持久化（异步 storage 封装）；401→single-flight 刷新→重放；刷新失败清态跳登录。不预设寿命，以响应为准。
- 会话：单设备互踢（§7.4）+ device_id 绑定（§7.3）+ 登出 `/connect/revocation`（§7.5）。
- 详见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》。

### 10.4 web-client（预留外部）
- authorization_code + PKCE，scope=api:web，预留给予 OpenFindBearings 之外的接入方；本期不启用。

### 10.5 重要约定：业务鉴权不信 JWT role
- Identity 自管理台用 token 里的 role；**OpenFindBearings 业务系统（API/Sync）不用 JWT 的 role claim 鉴权，一律查各自库的权限表/成员表动态判定**。
- 原因：JWT 的 role 来自 Identity 库（仅 SuperAdmin/Admin/User/TestUser），而业务侧 MerchantAdmin/MerchantStaff 等在 API 库；现状 `PermissionService.IsMerchantAdmin()` 误读 JWT claim → 恒 false（属 API 侧 bug，见 §12.2）。

---

## 11. 服务层 / 种子数据 / 管理台 / 部署

- 服务：ClientService/ScopeService/UserService/TenantService/RoleService（新增 Update 重命名）/TokenRevocationService（新增）/TenantResolver/AuditLogService/SystemConfigService。
- 种子：2 租户、4 角色（SuperAdmin/Admin/User/TestUser）、7 用户、4 客户端、4 Scope，均幂等（CreateIfNotExists + 权限追加补丁）；业务管理员 AuthUserId 固定 GUID（与 API SeedData 桥接一致，改动须同步 API 侧 `ServiceConstants`）。
- 管理台（自管理，v2.12.0 补全）：仪表盘（计数走各 service `GetCountAsync`，Guid 键实体，不再查空壳表恒 0）、用户列表+编辑（资料/角色整体替换）、角色 CRUD、客户端 CRUD（Keycloak 式富字段编辑）、Scope CRUD（含受众编辑）、租户、审计、系统配置。
- 部署：HTTP 5112 / HTTPS 7201；PostgreSQL db_identity（连接串 `Timezone=UTC`）；证书经 K8s Secret（密码缺失快速失败）；DP 密钥 hostPath。

---

## 12. 已知问题与专项（交叉引用）

1. **Admin OIDC RP 标准化**（Admin 项目专项）：state 未校验/JWT 不验签/`changepwd` hack 仍在（刷新竞态已解）。标准化为 AddOpenIdConnect 可解，但须先处理 device_id 与标准 handler 刷新的兼容。约 2-4 天 + 回归。不阻塞移动端 P0-P4。
2. **API 侧两个 bug**（API 项目，非 Identity）：① 商户审核门缺失；② `PermissionService.IsMerchantAdmin()` 读 JWT claim 恒 false。详见《移动端登录与商户入驻设计-v1.2.0》与 API 文档。
3. **Admin 面板权限未接线**（Admin 项目专项）：`db_admin` 的 `AdminRolePermission`/`AdminUserRole`（admin/editor/viewer）只有增删改 UI，无请求路径读取；cookie 主体无面板角色 claim；左侧菜单全量渲染。操作员/审计员分工需专项：面板角色来源（claim 或 API 拉取）→ 菜单按权限隐藏 → 控制器 policy。与"Identity Admin 与业务 Admin 同名双轨仅靠硬编码 GUID 桥接"一并规划。
4. **Sync/Crawler 端点门禁不均**：Sync `/api/etl`、`/api/monitor`、`/api/images`、`/api/sync/manual`、`/api/merchant/products` 匿名可触发；Crawler API 全匿名（含 `POST /{name}/run`）。属各项目专项，非 Identity 侧。

---

## 13. 与其它文档的关系

- 移动端登录/注册/商户入驻的**前端与 BFF 侧设计**见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》；本文是 **Identity 侧权威认证设计**，两者交叉引用、不重复。
- 商户成员模型/状态机/apply 契约的**业务侧**见 API《06-商户入驻与认证体系》（需与本文 §7.4/§10.3 及 Taro v1.2.0 对齐升版）。
- 近三期会话的过程记录见《docs/认证授权-本次会话交接-v1.0.0/v1.1.0/v1.2.0.md》。
