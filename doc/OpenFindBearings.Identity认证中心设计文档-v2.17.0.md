# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.17.0
**日期：** 2026-09-21
**状态：** 文档与代码同步（v2.15.0 S9 服务间用户查询端点落地）

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 ~ v2.10.0 | 2026-05 ~ 09 | 见历史版本文件（用户/角色/租户隔离/OIDC 端点/SMS grant/设备绑定/客户端命名统一等） |
| v2.11.0 | 2026-09-08 | 移动端登录与商户入驻设计评审结论纳入；提出 P1 安全完善清单 S1-S9 |
| v2.12.0 | 2026-09-10 | ① access 寿命定案 10 分钟；② S1-S9 按已实现记录；③ §5.2 受众编辑、§5.3 客户端管理修复按落地情况更新；④ §9 管理端点角色门禁已补齐；⑤ §4 补 OpenIddict 双表合并 + 表名去 Oidc 前缀；⑥ §8 新增 S10 注册用户默认角色 |
| v2.13.0 | 2026-09-11 | ① §13 移除断链引用（交接文档已删除、Taro v1.2.0 不存在）；② §6.1 补 QQ/Biometric grant stub；③ §2.1 修正 TenantContextMiddleware 描述（仅解析 realm、不返回 400）；④ §8 修正 SeedData 行号引用；⑤ §11 补 Program.cs 安全头中间件；⑥ §11 新增管理台 UI 功能清单（菜单/仪表盘/用户/租户/客户端/Scope/角色/登录/改密） |
| v2.13.1 | 2026-09-11 | 代码审查对齐修正：① §11.2 安全头改为内联 lambda（非独立类）+ 管道顺序与代码对齐；② §6.1 移除不存在的 `alipay` 常量（仅 `ServiceExtensions` 注释占位）；③ §11.1 补 `SmsCodeService`；④ §6.1 摘要补 WeChat；⑤ §11.3 Scope 受众列显示格式改为"（无）"+ `<code>` 块；⑥ §11.3 改密后强制重登行为补充 |
| v2.14.0 | 2026-09-12 | 商户入驻整体落地交叉引用同步：① §12.2 "API 侧两个 bug"更新为**已修复**（审核门 approve 端点已补齐并与 verify 分离；IsMerchantAdmin 恒 false 已改为查 MerchantMember 成员表 + CurrentMerchantId）；② §10.5 重要约定补充修复落地说明；③ 引用《移动端登录与商户入驻设计》由 v1.1.0 更新为 **v1.2.0**（§7.4/§10.3/§13 共 6 处）；④ §13 与其它文档关系更新为 API《06-商户入驻与认证体系-v2.0.0》+ Taro v1.2.0，并说明商户成员模型/状态机/apply 契约对齐完成 |
| v2.15.0 | 2026-09-21 | S9 服务间用户查询落地：新增 `Controllers/UsersApiController.cs`（`GET api/users/by-phone` / `GET api/users/by-email`，返回 `{exists, userId(Guid sub), nickname, phoneNumber, email}`），AllowAnonymous + 集群内网隔离（与 SmsController 同款信任边界，Ingress 不暴露）；系 API 员工邀请确认制（《06 v2.10.0》）的前置依赖——此前端点不存在导致 AddStaff 恒走"未注册发邀请"分支。OpenIddict 注册/scope/端点处理器零改动。 |
| v2.17.0 | 2026-09-24 | **管理面租户作用域收紧**：① 身份基础设施管理面（用户/角色/租户/Scope/客户端五控制器）挂 IdentitySystemAdmin Policy（SuperAdmin/Admin 角色 + tenant_id=system 声明，声明由 ApplicationClaimsPrincipalFactory 登录时写入 cookie）；② /api/account/admin/users 列表收紧——非 system 调用者强制锁定本租户（原 request.TenantId 可越权列举任意租户）；单条操作既有 GetTenantUserAsync 租户匹配不变；③ 决策记录：多设备共存不互踢——refresh_token 绑定 device_id 防令牌盗用已落地，互踢（新登录踢旧设备）经评估不做（商户多设备为真实需求，主流电商/工具类均允许多在线），登录设备管理页挂账；④ Admin 后台权限体系接线 API RBAC（登录门禁+permission claim+30 分钟复核），Identity 角色仅承载认证中心自管理门禁。 |
| v2.16.0 | 2026-09-22 | **注销/匿名化内部端点**（UsersApiController 扩展，对齐 API《06 v2.14.0》账户注销真闭环）：`POST /api/users/deactivate`（按 subject 软删除账户=禁用+永久锁定+DeletedAt，并吊销该用户全部刷新令牌实现全设备下线）；`POST /api/users/anonymize`（冷静期满由 API 定时任务调用：清手机号/邮箱、用户名改 deleted-{guid} 占位、刷新 SecurityStamp 使残留会话失效）。均 AllowAnonymous + 集群内网隔离（与 by-phone 同信任边界），不动 OpenIddict/OAuth 配置。 |

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

`TenantContextMiddleware` 在管道最前端（`UseAuthentication` 前）解析租户并缓存到 `HttpContext.Items["TenantInfo"]`，后续 `ITenantResolver.ResolveAsync()` 读缓存。

**解析方式**：中间件当前仅支持 `realm=租户名称`（推荐，各接入系统默认）→ 查 Tenants 表按 Name 匹配。支持四种传入位置：查询串、表单体、`X-Realm` 头、`ReturnUrl` 查询参数。

**空 realm 处理**：中间件不返回 400，而是创建空 `TenantInfo`（`TenantId == null`）继续管道。400/403 拒绝发生在各端点/控制器层（如 `AuthorizationController` 在 `tenantInfo.TenantId == null` 时返回 Forbid）。

> 注：文档历史版本曾记载 `tenant_id=GUID` 参数和"两者皆空拒绝 400"，属设计设想，实际中间件未实现。`tenant_id` GUID 匹配由 `ITenantResolver` 在服务层支持，不走中间件。

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
| OidcApplication | `Applications` |
| OidcAuthorization | `Authorizations` |
| OidcScope | `Scopes` |
| OidcToken | `Tokens` |

**双表合并与表名去前缀（v2.12.0 落地）**：历史上 `options.UseOpenIddict()` 与自定义实体并存，导致库里多出一套 0 行的默认 string 键 `OpenIddict*` 壳表（真数据一直在带 `Oidc` 前缀的 Guid 键表）。收口方式：删除 `UseOpenIddict()` 注册；壳表清除后前缀失去区分意义，实体直接映射裸名（上表）。**迁移历史重建为单一 `InitialCreate(20260910111742)`** 直建裸名表全套（旧的 InitialCreate/Consolidate/DropOidcTablePrefix 三个迁移文件已删除），服务层读写与仪表盘计数统一走 `OpenIddictEntityFrameworkCoreApplication/Scope<Guid>` 等 Guid 键实体。

**迁移重建的运维含义**：迁移 ID 集合与旧库 `__EFMigrationsHistory` 不再对应，**存量库必须 drop 重建**（由启动 seed 自动建表+种子），不能原地升级。线上 db_identity 已按此重建并验证（16 表、裸名、登录恢复）；本地库下次启动前同样需 drop 重建。库内与 Users/Roles/UserTokens/Tenants 等既有表无重名冲突；无外部直连方（Admin/API/Sync 均不碰 db_identity）。

---

## 5. 客户端注册表（现状，源自 SeedData）

| ClientId | 类型 | 显示名 | 授权类型 | 端点/关键权限 | Scope | 重定向 |
|---|---|---|---|---|---|---|
| `sync-client` | 机密（有 secret） | 同步服务客户端 | client_credentials、refresh_token | Token | api:sync | 无（M2M） |
| `mobile-client` | **公开**（无 secret） | 移动端 Taro | password、sms（custom）、refresh_token | Token、**Revocation** | api:mobile | 无（直连 token） |
| `web-client` | 机密 | WEB 客户端（预留外部） | authorization_code、refresh_token | Authorization、Token、EndSession、Code、**PKCE 必需** | api:web | localhost:5002/signin-oidc |
| `admin_client` | 机密 | Admin 后台管理 | authorization_code、refresh_token | Authorization、Token、EndSession、Code；ConsentType=Implicit | openid、api:admin、api:mobile、**offline_access** | admin.515813.xyz/callback、/signout-callback-oidc |

> 已落地：`mobile-client` 已补 `Permissions.Endpoints.Revocation`；`admin_client` 已补 `scp:offline_access`（授权码流程签发 refresh_token 的前提，Admin 无感续期的根修）。两处均配 SeedData 幂等补丁 `EnsureClientPermissionsAsync`（CreateIfNotExists 只建不改 → 对已存在客户端**只追加缺失权限、不覆盖既有字段**），老库发布新镜像即自愈，免手工 SQL。
> [待实施 P1] SeedData 内 client secret（`SeedData.cs:459/501/527`）仍为明文常量，须移出源码、改 K8s Secret 注入（证书密码部分已完成，见 §8 S4）。

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
- **现状（v2.12.0 落地）**：受众已可在 Scope 管理 UI 编辑——`ScopeService.UpdateAsync` 支持整体替换/保留 Resources（不传即不动）。资源↔scope 的**初始**映射仍在 SeedData（`ApiResourceConstants`）。
- **UI 组件（`_AudienceEditor.cshtml` 共享 partial）**：Keycloak 式行级编辑器，Scope 的 Create 和 Edit 页面复用：
  - 已有受众以行展示，每行带"移除"按钮（客户端 JS 删除行 + 隐藏字段）
  - 输入框带 `datalist` 自动建议，数据源汇总 `ApiResourceConstants` + 各 Scope 已有受众（去重）
  - 支持回车添加、点击"添加"按钮添加，自动去重
  - 隐藏字段 `Resources` 列表供表单提交；`resourcesSubmitted` 隐藏标记区分"显式清空"与"字段不存在"
  - Scope 列表页新增受众列（每项以 `<code>` 块渲染），无受众显示"（无）"
- **客户端编辑页受众预览**：编辑页 JavaScript 根据勾选的 AllowedScopes 实时计算并展示 token 的 `aud` 并集（`ScopeAudiences` JSON 由控制器注入），帮助管理员直观预览签发的受众。
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

**注释占位（未注册，NotImplementedException stub）**：
| Grant | 常量 | 状态 |
|---|---|---|
| `wechat` | `GrantTypeConstants.WeChat` | 注释占位，P5+ 待企业认证+手机号授权资质 |
| `qq` | `GrantTypeConstants.QQ` | 代码 stub（`HandleQQAsync`），未注册 `AllowCustomFlow` |
| `biometric` | `GrantTypeConstants.Biometric` | 代码 stub（`HandleBiometricAsync`），未注册 `AllowCustomFlow` |

> `wechat`/`qq`/`biometric` 仅存在于 `Constants/GrantTypeConstants.cs` 与 `AuthorizationController` 的 `NotImplementedException` handler，未在 `ServiceExtensions` 注册，当前不可达。
> 注：`alipay` 在 `ServiceExtensions` 有注释占位的 `AllowCustomFlow("alipay")`，但无对应常量、无 handler 方法，因此不单列。

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
| S4 | 机密出源码 | **部分** | 已完成：生产证书密码去默认值，缺失配置快速失败（K8s Secret 注入）。未完成：SeedData 三个 client secret 仍明文常量（sync-client :459、web-client :501、admin_client :527）。 | P1 |
| S5 | Data Protection 持久化 | 已完成 | `Program.cs` 按 `DataProtection:KeysPath` 启用；K3s 配 hostPath `/app/dpkeys`（单副本）。Pod 重启后 OIDC 关联 state/认证 cookie 不再失效。 | P1 |
| S6 | mobile-client revocation 权限 | 已完成 | SeedData 新库直配 + 老库 `EnsureClientPermissionsAsync` 幂等补丁（admin_client offline_access 同机制）。 | P1 |
| S7 | access 寿命 | 已完成 | **定案 10 分钟**（不再改 5）。 | P1 |
| S8 | SMS 真实发送 + 免密注册 | 部分 | 已做：DevMode 配置化（生产默认随机码）+ 发送频控。未做：真实短信通道、SignUp 密码可选。 | P2 |
| S9 | 服务间用户查询 | 已完成 | **v2.15.0 落地**：新增 `UsersApiController`（`api/users/by-phone` / `api/users/by-email`，AllowAnonymous + 集群内网隔离，与 SmsController 同款信任边界），API 员工邀请链路按此查询注册用户；未采用 M2M token 方案（辅助只读端点无需完整 OAuth 开销）。OpenIddict 配置零改动。 | P2/P4 |
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
- 商户入驻/团队管理的移动侧契约见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》，业务侧见 API《06-商户入驻与认证体系设计文档-v2.0.0.md》。

### 10.4 web-client（预留外部）
- authorization_code + PKCE，scope=api:web，预留给予 OpenFindBearings 之外的接入方；本期不启用。

### 10.5 重要约定：业务鉴权不信 JWT role
- Identity 自管理台用 token 里的 role；**OpenFindBearings 业务系统（API/Sync）不用 JWT 的 role claim 鉴权，一律查各自库的权限表/成员表动态判定**。
- 原因：JWT 的 role 来自 Identity 库（仅 SuperAdmin/Admin/User/TestUser），而业务侧 MerchantAdmin/MerchantStaff 等在 API 库。
- **修复落地（v2.14.0）**：原 `PermissionService.IsMerchantAdmin()` 误读 JWT claim → 恒 false 的缺陷已修复——改为查 `MerchantMember` 成员表（当前用户 + CurrentMerchantId 维度，Role=MerchantAdmin 且 Active）。商户成员模型/审核门 apply 契约的权威设计见 API《06-商户入驻与认证体系设计文档-v2.0.0.md》。

---

## 11. 服务层 / 种子数据 / 管理台 / 部署

### 11.1 服务与种子
- 服务：ClientService/ScopeService/UserService/TenantService/RoleService（新增 Update 重命名）/TokenRevocationService（新增）/SmsCodeService（验证码生成/校验/频控）/TenantResolver/AuditLogService/SystemConfigService。
- 种子：2 租户、4 角色（SuperAdmin/Admin/User/TestUser）、7 用户、4 客户端、4 Scope，均幂等（CreateIfNotExists + 权限追加补丁）；业务管理员 AuthUserId 固定 GUID（与 API SeedData 桥接一致，改动须同步 API 侧 `ServiceConstants`）。

### 11.2 Program.cs 管道与中间件

实际管道顺序（`Program.cs:87-122`）：

```
UseForwardedHeaders()                  ← K8s ingress 注入 X-Forwarded-For/Proto
UseRateLimiter()                       ← GlobalLimiter: /connect/*、signup、send-code 30次/分
UseHttpsRedirection()                  ← HTTP→HTTPS
内联安全头 lambda                       ← X-Frame-Options: DENY, X-Content-Type-Options: nosniff
UseRouting()                           ← 路由匹配
UseCors("AllowSpecificOrigins")        ← 跨域策略
MapStaticAssets()                      ← 静态文件（认证前，避免 CSS/JS 走认证检查）
UseTenantContext()                     ← 扩展方法，解析 realm（必须在认证前）
UseAuthentication()
UseAuthorization()
UseMiddleware<AuditLogMiddleware>()     ← 审计日志（认证之后，读取操作人身份）
```

> 注：安全头通过内联 `app.Use(async (ctx, next) => { ... })` 实现，非独立中间件类。`UseTenantContext()` 是 `TenantContextMiddleware` 的扩展方法包装。

### 11.3 管理台 UI 功能清单

#### 侧边栏导航（`_Layout.cshtml`）
静态侧边栏（240px 宽、深色主题），菜单项按当前控制器自动高亮：

| 菜单 | 控制器 | 路由 | 图标 |
|---|---|---|---|
| 仪表盘 | Home | `/` | `bi-speedometer2` |
| 租户管理 | Tenant | `/Tenant` | `bi-building` |
| 用户管理 | Users | `/Users` | `bi-people` |
| 客户端管理 | Application | `/Application` | `bi-key` |
| Scope 管理 | Scope | `/Scope` | `bi-shield-check` |
| 角色管理 | Role | `/Role` | `bi-person-badge` |

底部管理员下拉：修改密码 → `/profile/change-password`；退出登录 → POST `/Account/Logout`。

#### 仪表盘（Home/Index）
4 张统计卡片（用户数/租户数/客户端数/Scope 数）+ 4 个快捷导航按钮。

#### 用户管理（Users/Index + Create + Edit）
| 功能 | 说明 |
|---|---|
| 列表 | 分页表格，显示用户名/邮箱/手机号/租户/状态/创建时间 |
| 搜索 | 按用户名或邮箱文本搜索 |
| 租户筛选 | 下拉框按租户过滤（系统管理员看全部） |
| 创建 | 表单：用户名/邮箱/密码/租户/手机号/姓名/角色（复选框） |
| 编辑 | 只读：用户名/状态/角色/创建时间/最后登录时间。可编辑：邮箱/手机/姓名/昵称/性别/生日/头像URL/语言/时区/角色（整体替换） |
| 启用/禁用 | 内联 POST 按钮 |
| 重置密码 | Bootstrap Modal，新密码字段（最少 6 字符） |
| 删除 | JS confirm 确认后删除 |

#### 租户管理（Tenant/Index + Create + Edit）
| 功能 | 说明 |
|---|---|
| 列表 | 分页表格，显示名称/描述/用户数/状态/创建时间 |
| 搜索 | 按租户名称搜索 |
| 创建 | 名称 + 描述 |
| 编辑 | 名称 + 描述 + 启用复选框 |
| 删除 | JS confirm 确认后删除 |

#### 客户端管理（Application/Index + Create + Edit）
| 功能 | 说明 |
|---|---|
| 列表 | 分页表格，显示 ClientId/显示名/类型 |
| 搜索 | 文本搜索 |
| 创建 | 租户/ClientId/显示名/secret（可选）/回调URI/是否公开复选框 |
| 编辑 | Keycloak 式富字段：显示名/访问类型下拉（confidential/public）/同意要求下拉（explicit/implicit/external/none）/回调URI（每行一个）/登出回调URI（每行一个）/AllowedScopes 复选框（写 `scp:*` 权限）/ClientId/Permissions 只读展示 |
| 实时受众预览 | JS 根据勾选的 Scopes 实时计算 token 的 aud 并集展示 |
| 重发 secret | 列表页按钮，点击后弹出新 secret |
| 删除 | JS confirm 确认后删除 |

#### Scope 管理（Scope/Index + Create + Edit）
| 功能 | 说明 |
|---|---|
| 列表 | 分页表格，显示名称/显示名/描述/**受众列**（每项 `<code>` 块渲染，无受众显示"（无）"） |
| 搜索 | 文本搜索 |
| 创建 | 租户/名称（带 `api:system` 格式提示）/显示名/描述/**受众编辑器**（`_AudienceEditor.cshtml`） |
| 编辑 | 名称（只读）/显示名/描述/**受众编辑器** |
| 删除 | JS confirm 确认后删除 |

**受众编辑器交互**：
- 已有受众以行展示，每行带"移除"按钮
- 输入框带 `datalist` 自动建议（数据源：`ApiResourceConstants` + 各 Scope 已有受众去重）
- 支持回车或"添加"按钮添加新受众，自动去重
- 隐藏字段列表供表单提交；`resourcesSubmitted` 标记区分"显式清空"与"字段不存在"

#### 角色管理（Role/Index + Create + Edit）
| 功能 | 说明 |
|---|---|
| 列表 | 分页表格，显示角色名/用户数 |
| 搜索 | 按角色名搜索 |
| 创建 | 角色名（带唯一性提示） |
| 编辑 | 角色名（提示：重命名同步更新所有已分配用户） |
| 删除 | JS confirm 确认后删除 |

#### 修改密码（Profile/ChangePassword）
独立页面（渐变登录背景风格），表单：当前密码/新密码/确认新密码（最少 6 字符），支持 return URL 回跳。**改密成功后强制 `SignOutAsync` 并跳转登录页**（用户需重新登录）。

#### 登录页（Login/Login）
表单：用户名 + 密码，动态显示租户/Realm 显示名，支持 return URL，CSRF token。

### 11.4 部署
- HTTP 5112 / HTTPS 7201；PostgreSQL db_identity（连接串 `Timezone=UTC`）；证书经 K8s Secret（密码缺失快速失败）；DP 密钥 hostPath。
- 容器 uid=1654(app)；hostPath 卷 `chown -R 1654:1654`。

---

## 12. 已知问题与专项（交叉引用）

1. **Admin OIDC RP 标准化**（Admin 项目专项）：state 未校验/JWT 不验签/`changepwd` hack 仍在（刷新竞态已解）。标准化为 AddOpenIdConnect 可解，但须先处理 device_id 与标准 handler 刷新的兼容。约 2-4 天 + 回归。不阻塞移动端 P0-P4。
2. **API 侧两个 bug 已修复**（API 项目，v2.14.0 更新）：
   - ① 商户审核门缺失 → 已补齐 `POST /api/admin/merchants/{id}/approve`（Pending→Active），与 verify 认证分离，商户审核通过后 C 端可见。
   - ② `PermissionService.IsMerchantAdmin()` 读 JWT claim 恒 false → 已改为查 `MerchantMember` 成员表 + `CurrentMerchantId`（X-Merchant-Id 上下文），AddStaff/RemoveStaff 管理端校验生效。
   - 详见《移动端登录与商户入驻设计-v1.2.0》与 API《06-商户入驻与认证体系设计文档-v2.0.0.md》。
3. **Admin 面板权限未接线**（Admin 项目专项）：`db_admin` 的 `AdminRolePermission`/`AdminUserRole`（admin/editor/viewer）只有增删改 UI，无请求路径读取；cookie 主体无面板角色 claim；左侧菜单全量渲染。操作员/审计员分工需专项：面板角色来源（claim 或 API 拉取）→ 菜单按权限隐藏 → 控制器 policy。与"Identity Admin 与业务 Admin 同名双轨仅靠硬编码 GUID 桥接"一并规划。
4. **Sync/Crawler 端点门禁不均**：Sync `/api/etl`、`/api/monitor`、`/api/images`、`/api/sync/manual`、`/api/merchant/products` 匿名可触发；Crawler API 全匿名（含 `POST /{name}/run`）。属各项目专项，非 Identity 侧。

---

## 13. 与其它文档的关系

- 移动端登录/注册/商户入驻的**前端与 BFF 侧设计**见《OpenFindBearings.Taro/doc/01-架构设计/移动端登录与商户入驻设计-v1.2.0.md》；本文是 **Identity 侧权威认证设计**，两者交叉引用、不重复。
- 商户成员模型/状态机/apply 契约的**业务侧**见 API《06-商户入驻与认证体系设计文档-v2.0.0.md》（v2.14.0 已对齐 §7.4/§10.3 及 Taro v1.2.0）。
- 会话历史记录已归档至项目记忆（session memory），不再维护独立交接文档。
