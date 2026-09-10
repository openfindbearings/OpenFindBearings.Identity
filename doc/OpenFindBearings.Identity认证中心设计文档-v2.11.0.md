# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.11.0
**日期：** 2026-09-08
**状态：** 现状与代码同步 + 待完善项已设计（标注 [待实施]）

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 ~ v2.10.0 | 2026-05 ~ 09 | 见历史版本文件（用户/角色/租户隔离/OIDC 端点/SMS grant/设备绑定/客户端命名统一等） |
| v2.11.0 | 2026-09-08 | 纳入移动端登录与商户入驻设计评审结论：① 澄清 refresh 滚动轮换系 OpenIddict 默认且已生效；② 新增"单设备互踢（限 mobile-client）"会话策略设计；③ access token 寿命 10→5 分钟（缩短互踢/吊销生效窗口）；④ 新增令牌吊销设计（改密/重置/禁用/注销/登出，经 IOpenIddictTokenManager 编程调用，不改 grant/端点/handler）；⑤ 新增"安全完善待实施清单"（lockout、刷新查用户状态、机密出源码、Data Protection 持久化、mobile-client revocation 权限、SMS 真实发送、免密注册、服务间用户查询端点）；⑥ 新增第 10 章"各端对接指南"；⑦ 明确 OpenIddict 配置现可调整（保留还原兜底），但 grant/端点拓扑/租户模型仍保持稳定；⑧ Admin OIDC RP 标准化另立专项（交叉引用，不并入本文 to-do） |

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

## 4. OpenIddict 自定义实体

为在 OpenIddict 实体加 TenantId，定义 4 个继承类：OidcApplication（Clients 表）、OidcAuthorization（Authorizations）、OidcScope（Scopes）、OidcToken（Tokens，无 TenantId、经授权链隔离）。

---

## 5. 客户端注册表（现状，源自 SeedData）

| ClientId | 类型 | 显示名 | 授权类型 | 端点/关键权限 | Scope | 重定向 |
|---|---|---|---|---|---|---|
| `sync-client` | 机密（有 secret） | 同步服务客户端 | client_credentials、refresh_token | Token | api:sync | 无（M2M） |
| `mobile-client` | **公开**（无 secret） | 移动端 Taro | password、sms（custom）、refresh_token | Token | api:mobile | 无（直连 token） |
| `web-client` | 机密 | Web 客户端（预留外部） | authorization_code、refresh_token | Authorization、Token、EndSession、Code、**PKCE 必需** | api:web | localhost:5002/signin-oidc |
| `admin_client` | 机密 | Admin 后台管理 | authorization_code、refresh_token | Authorization、Token、EndSession、Code；ConsentType=Implicit | openid、api:admin、api:mobile | admin.515813.xyz/callback、/signout-callback-oidc |

> [待实施 P1] `mobile-client` 须补 `Permissions.Endpoints.Revocation`，否则移动端登出调 `/connect/revocation` 被拒。
> [待实施 P1] SeedData 内 client secret（sync/web/admin）与证书密码默认值 `"111111"` 须移出源码、改 K8s Secret 注入。

### 5.1 Scope 与资源（aud）模型
| Scope | 关联资源（token 的 aud） |
|-------|------|
| api:sync | openfindbearings-api |
| api:admin | openfindbearings-api、openfindbearings-sync |
| api:mobile | openfindbearings-api |
| api:web | openfindbearings-api |

每个后台微服务有独立资源标识；`api:admin` 关联全部服务资源，Admin token 携多 aud 可统一访问后台微服务。新增服务时在 `ApiResourceConstants` 加常量并追加到 `api:admin` 资源列表。

### 5.2 受众（资源/aud）的维护
- **模型**：OpenIddict 的 Scope 带 `Resources` 集合 = 该 scope 签发 token 的 `aud` 值；受众即后台微服务资源标识（openfindbearings-api / openfindbearings-sync）。
- **现状**：资源↔scope 映射在 SeedData 硬编码（`ApiResourceConstants`）；`ScopeService.CreateAsync` 支持设 Resources，但 `UpdateAsync` 仅保留现有 Resources、**不可改**，管理 UI 未暴露受众编辑；新增后台服务须改代码 + 重种子。
- **设计**（受众属基础设施级、与部署服务强绑定）：
  - 权威源 = 代码/SeedData。**新增服务步骤**：`ApiResourceConstants` 加常量 → 追加到相关 scope（通常 api:admin）的 Resources → 重种子/重启 → 各服务 `ValidAudiences` 同步。
  - 可选增强 [待实施 P1]：Scope 管理 UI 展示并允许编辑 scope→resource 映射（补 `UpdateScopeDto.Resources` + `UpdateAsync` 应用），免改代码即可调整受众。

### 5.3 客户端/Scope 管理的现状缺口与修复 [待实施 P1]
- **缺口（已核实）**：
  - `ClientService.UpdateAsync` 重建 descriptor 时**只回填 Permissions**，不回填 RedirectUris/PostLogoutRedirectUris/ConsentType/ClientType/DisplayName/Scopes → 保存一次即抹掉这些（OpenIddict 整体覆盖语义）。
  - `RegenerateSecretAsync` 同样重建 descriptor → 抹字段。
  - `CreateAsync` 硬编码 authorization_code 系权限集 + 单 RedirectUri → 无法正确创建公开客户端（如 mobile-client 的 password/sms 无 redirect）。
  - `ScopeService.UpdateAsync` 不可改 Resources（受众）。
- **修复设计**：
  - Update/RegenerateSecret 改"读-改-写全量"：从现有 application 填充 descriptor 全部字段再应用变更；RegenerateSecret 只改 secret。
  - CreateAsync 参数化：按 client 类型（公开/机密）+ 授权类型集合构建 descriptor，不硬编码。
  - Scope Update 支持改 Resources。
  - 属 Identity 自管理后台维护能力修复，独立于移动端登录线，可随 P1 安全完善一起做。

---

## 6. 授权类型与端点

### 6.1 服务端启用的 grant（ServiceExtensions）
`client_credentials`、`password`、`sms`（custom）、`authorization_code`、`refresh_token`。
`wechat`、`alipay` 为注释占位（`HandleWeChatAsync` 等是 NotImplementedException stub）——[待实施 P5+] 微信一键登录需企业认证 + 手机号授权资质，预留常量已存在（GrantTypeConstants.WeChat 等），届时启用。

### 6.2 OAuth/OIDC 端点
| 端点 | 用途 | 租户校验 |
|------|------|---------|
| `/connect/authorize` | 授权码流程入口（Admin/web） | 是 |
| `/connect/token` | 换/刷令牌（所有 grant） | 是 |
| `/connect/userinfo` | 用户信息 | 是 |
| `/connect/logout` | RP-Initiated Logout（浏览器 SSO 结束会话，需 end_session 权限） | 是 |
| `/connect/revocation` | 令牌吊销（移动端登出用，需 revocation 权限） | OpenIddict 内部 |

### 6.3 SMS 验证码
- `POST /api/sms/send-code`（匿名，含 SmsCodeType）。
- `grant_type=sms`：手机号 + 验证码校验通过即签发令牌；**首次使用自动建无密码 OIDC 用户**（登录即注册）。
- [待实施 P2] `SmsCodeService.SendAsync` 当前为开发桩（固定码 123456 + 日志），须接真实短信通道 + 日上限频控；`SignUp` 密码改可选以支持免密注册。

---

## 7. 令牌生命周期与会话策略

### 7.1 寿命（现状 → 调整）
| 令牌 | 现状 | 目标 | 说明 |
|---|---|---|---|
| access | 10 分钟 | **5 分钟** [待实施 P1] | 缩短"互踢/吊销/禁用"的生效窗口；全局配置，Admin/Sync 也随之更频繁刷新/重取 |
| refresh | 30 天 | 30 天 | 绝对有效期 |
| authorization_code | 默认 | 默认 | 一次性 |

### 7.2 滚动轮换（澄清）
**refresh 滚动轮换是 OpenIddict 默认行为、现已生效**（未调用 `DisableRollingRefreshTokens`）：每次刷新旧 refresh 标记 redeemed、响应返回新 refresh，并带 30 秒重用宽限（reuse leeway）。**无需任何配置**。因此客户端"刷新 single-flight"是纵深防御（非硬性必需）。

### 7.3 device_id 设备绑定（现状，保留）
- 登录（password/sms）读 `device_id` 写入 JWT claim；授权码流程写入授权码 principal；刷新时比对，不一致返回 invalid_grant；请求未带则不绑定。
- 语义：**防 refresh token 被复制到其它设备盗用**（刷新即时拒），**不是**单设备互踢。
- device_id 为客户端自报、服务端只做一致性比对——防误用/串设备，**不防伪造**（隐私文案不得承诺"防盗号"）。

### 7.4 单设备互踢（新设计，限 mobile-client）[待实施 P1]
- 目标：同账号在**移动端**只允许一台设备在线，新登录踢旧设备（微信式），但**按 client 隔离**——不影响 Admin 网页 / Sync M2M。
- 机制：mobile-client 的 password/sms 登录成功、签发新令牌**之前**，经 `IOpenIddictTokenManager`/token store **吊销该 subject 在 mobile-client 下的既有 refresh token**。
- 生效时延：旧设备手里 access token（≤5 分钟）过期后刷新被拒 → 掉线回登录页。**非秒踢**（无推送通道；秒踢需 reference token + introspection，本期不做）。
- 与 device_id 关系：互补——互踢管"同账号一台手机在线"，device_id 管"token 不被异机盗用"。两者都保留。
- 隔离保证：吊销只针对 (subject, mobile-client)，admin_client/sync-client/web-client 的令牌不受影响。

### 7.5 令牌吊销（新设计）[待实施 P1]
- 触发点：改密、重置密码、禁用用户、注销账户、移动端登出。
- 实现：Identity 内部用 `IOpenIddictTokenManager.RevokeAsync` / 按 subject(+application) 查找并吊销 refresh token——**编程调用 OpenIddict 提供的 API，不改 grant/端点/handler/租户模型**。
- 移动端登出：清本地 token + `POST /connect/revocation`（需 §5 的 revocation 权限）。`/connect/logout` 是浏览器 SSO 会话结束，对无 cookie 的移动端无意义。
- 残余窗口：access token（5 分钟）不可吊销，吊销/登出后最长 5 分钟内旧 access 仍可用（行业常规）。

---

## 8. 安全完善待实施清单（Identity 侧）

| # | 项 | 现状 | 目标 | 阶段 |
|---|---|---|---|---|
| S1 | 账户锁定 lockout | `ServiceExtensions` 三行被注释、禁用 | 启用 Lockout（或 token 端点限流），防直连 `/connect/token` 暴力破解（Identity 公网可达，仅靠 BFF 限流不够） | P1 |
| S2 | 刷新查用户状态 | `HandleRefreshTokenAsync` 未调 `CheckCanLoginAsync` | 补上，禁用即时生效（与 authorize/password/sms 对齐） | P1 |
| S3 | 令牌吊销 | 全站零吊销 | 见 §7.5，改密/重置/禁用/注销/登出吊销 | P1 |
| S4 | 机密出源码 | SeedData client secret、证书密码 `"111111"` 明文 | 改 K8s Secret 注入 | P1 |
| S5 | Data Protection 持久化 | 无持久化，Pod 重启 SSO 掉线 | 落持久卷/Redis | P1 |
| S6 | mobile-client revocation 权限 | 缺 | 补 `Permissions.Endpoints.Revocation` | P1 |
| S7 | access 寿命 | 10 分钟 | 5 分钟 | P1 |
| S8 | SMS 真实发送 + 免密注册 | 开发桩；SignUp 密码必填 | 接短信通道 + 频控；SignUp 密码可选 | P2 |
| S9 | 服务间用户查询 | API 调的 `/api/users/by-phone`、`/register` 页等**不存在**（邀请链路死） | API 改持 M2M token 调 `/api/account/admin/users`，或 Identity 补服务间查询端点；邀请落地页改指 Taro H5 注册页带 inviteCode | P2/P4 |

> OpenIddict 配置现已可调整（用户放开，保留还原兜底）；但 grant/端点拓扑/租户模型/handler 主逻辑仍力求稳定，上述完善项优先用"编程调用 Manager API + 配置项 + 种子数据"实现，避免重写认证管道。

---

## 9. API 端点（AccountController / SmsController / AuditLog / SystemConfig）

（与 v2.10.0 一致，摘要）
- `/api/account/signup`（匿名，注册，请求体 SignUpRequest{account,password,confirmPassword,agreeTerms,realm,inviteCode?}，**只返回 UserResponse 不返回 token**）
- `/api/account/me`、`/me/profile`、`/me/change-password`、`/me/account`(软删)（OpenIddict Bearer）
- `/api/account/admin/users` CRUD + `/permanent`(物理删，仅已软删) + `/status` + `/unlock` + `/reset-password` + `/restore`（Bearer + SuperAdmin/Admin）
- `/api/sms/send-code`（匿名）
- `/api/auditlog/*`、`/api/systemconfig/*`（Bearer + SuperAdmin/Admin）

> [待实施 P1] 现状风险：Users/Tenant 等管理控制器仅 `[Authorize]`（Cookie），**无角色门禁**——任何登录用户（含 SMS JIT 无角色用户）持自管理 Cookie 即可访问管理端点。须补 SuperAdmin/Admin 角色门禁。

---

## 10. 各端对接指南

### 10.1 Admin 后台（admin_client，authorization_code）
- 流程：浏览器重定向 `/connect/authorize`（带 realm、scope=openid api:admin api:mobile、PKCE 视配置）→ 登录 → code 回 `/callback` → 换 token。
- 现状：**手写 OIDC RP**（非标准 AddOpenIdConnect），token 存 HttpOnly cookie 的 claims，`BearerTokenHandler` 从 claims 取 token 调 API/Sync。
- device_id：Admin 生成随机 Guid 存 HttpOnly cookie，附 authorize URL 与 token 请求。
- 已知债（另立专项，不并入移动端线）：state 生成后未校验（登录 CSRF）、JWT 只 Base64 解不验签、刷新竞态、`state=="changepwd"` hack。**标准化为 AddOpenIdConnect 可一次性解决**，但标准 handler 内部刷新**带不了自定义 device_id** → 须先决定"Admin 放弃 device_id 或子类化 handler"，约 2-4 天 + 回归。见 §12 专项。
- 单设备互踢**不影响** Admin（互踢限 mobile-client）。

### 10.2 Sync 服务（sync-client，client_credentials）
- M2M：`/connect/token` 用 client_credentials + scope=api:sync 取 token（aud=openfindbearings-api），进程级缓存、透明刷新（约 5 分钟窗口）。
- 无 refresh token 交互、无 device_id、无用户上下文。
- access 寿命改 5 分钟后，Sync 的 token 缓存窗口应相应调到 ~4 分钟，避免临界过期。
- Sync 自身 API 的 ValidAudiences 含 [openfindbearings-sync, openfindbearings-api, api:sync]。

### 10.3 移动端（mobile-client，password/sms，经 BFF）
- **Taro 不直连 Identity**，统一经 BFF（OpenFindBearings.Mobile）：
  - 注册 `POST /mobile/auth/register` → BFF 链式调 Identity `signup` + `password` grant，返回 token。
  - 登录 `POST /mobile/auth/login`（username/password/deviceId）、`/login-sms`（phone/code/deviceId）、发码 `/send-code`、刷新 `/refresh`。
- BFF→Identity 的 `/connect/token` 必须带 `client_id=mobile-client`、`realm=openfindbearings`、`scope=api:mobile`（否则租户关拒绝 / token 无 aud / API 401）。
- BFF `Identity:Audience` 须为资源名 `openfindbearings-api`（非 api:mobile）。
- 令牌策略（Taro 侧）：access 仅内存、refresh 持久化；401→single-flight 刷新→重放；刷新失败清态跳登录。
- 会话：mobile-client 单设备互踢（§7.4）+ device_id 绑定（§7.3）。
- 详见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》。

### 10.4 web-client（预留外部）
- authorization_code + PKCE，scope=api:web，预留给予 OpenFindBearings 之外的接入方；本期不启用。

### 10.5 重要约定：业务鉴权不信 JWT role
- Identity 自管理台用 token 里的 role；**OpenFindBearings 业务系统（API/Sync）不用 JWT 的 role claim 鉴权，一律查各自库的权限表/成员表动态判定**。
- 原因：JWT 的 role 来自 Identity 库（仅 SuperAdmin/Admin/User/TestUser），而业务侧 MerchantAdmin/MerchantStaff 等在 API 库；现状 `PermissionService.IsMerchantAdmin()` 误读 JWT claim → 恒 false（属 API 侧 bug，见 §12）。

---

## 11. 服务层 / 种子数据 / 部署

（与 v2.10.0 一致，摘要）
- 服务：ClientService/ScopeService/UserService/TenantService/TenantResolver/AuditLogService/SystemConfigService。
- 种子：2 租户、4 角色（SuperAdmin/Admin/User/TestUser）、7 用户、4 客户端、4 Scope，均幂等（CreateIfNotExists）。
- 部署：HTTP 5112 / HTTPS 7201；PostgreSQL db_identity；开发证书。
- [待实施 P1] Data Protection 持久化（S5）；机密出源码（S4）。

---

## 12. 已知问题与专项（交叉引用，不并入本文 to-do）

1. **Admin OIDC RP 标准化**（Admin 项目专项）：手写 RP 的 state 未校验/JWT 不验签/刷新竞态；标准化为 AddOpenIdConnect 可解，但须先处理 device_id 与标准 handler 刷新的兼容。约 2-4 天 + 回归。不阻塞移动端 P0-P4。
2. **API 侧两个今天就坏的 bug**（API 项目，非 Identity）：① 商户审核门缺失（无处调 `Merchant.Approve()`，审批通过仍 Pending、C 端不可见）；② `PermissionService.IsMerchantAdmin()` 读 JWT claim 恒 false。详见《移动端登录与商户入驻设计-v1.2.0》与 API 文档。
3. **管理控制器无角色门禁**（Identity，§9 注）：[待实施 P1] 补 SuperAdmin/Admin 门禁。

---

## 13. 与其它文档的关系

- 移动端登录/注册/商户入驻的**前端与 BFF 侧设计**见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》；本文是 **Identity 侧权威认证设计**，两者交叉引用、不重复。
- 商户成员模型/状态机/apply 契约的**业务侧**见 API《06-商户入驻与认证体系》（需与本文 §7.4/§10.3 及 Taro v1.2.0 对齐升版）。
