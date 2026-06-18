# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.2.0  
**日期：** 2026-06-16  
**状态：** 已实施（租户隔离完成）

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 | 2026-05-07 | 初始版本：用户管理、角色管理、OpenIddict 基础配置 |
| v1.0.1 | 2026-06-01 | 新增 restore 端点 |
| v1.1.0 | 2026-06-12 | 新增 Tenant 基础设施、OIDC 授权端点、登录页 |
| v2.0.0 | 2026-06-12 | Controller 架构重新设计：MVC 自身管理 + API 外部调用分离；清理冗余角色；admin_client scope 改为 api:admin |
| v2.1.0 | 2026-06-15 | 全量实施 MVC 管理页面；TenantService/TenantController；删除 RoleController |
| v2.2.0 | 2026-06-16 | 双 cookie 分离隔离；OIDC 全部端点租户校验；管理控制器锁 Management cookie；UserService 租户范围查询；SignUp 加 realm；开放重定向修复 |

---

## 1. 项目定位

OpenFindBearings.Identity 是全局 OIDC 认证中心，同时承载两套独立系统：

### 1.1 两套系统，一个进程

| | 自管理后台 | OIDC 认证服务 |
|---|---|---|
| 用途 | 管理用户/租户/客户端/Scope | 为 Admin/App/Sync 提供 OAuth/OIDC 认证 |
| 入口 | 直接访问 `https://localhost:7201/` | 被 OAuth authorize 重定向 |
| Cookie 方案 | `Identity.Management`（`.AspNetCore.Identity.Management`） | `Identity.Application`（`.AspNetCore.Cookies`） |
| Controller 锁 | `[Authorize(AuthenticationSchemes = "Identity.Management")]` | 显式读 `IdentityConstants.ApplicationScheme` |
| 登录 | POST `/Account/Login`（returnUrl 不含 /connect/authorize） | POST `/Account/Login`（returnUrl 以 /connect/authorize 开头） |
| 退出 | POST `/Account/Logout`（只清 Management） | GET/POST `/connect/logout`（只清 Application） |
| 用户池 | 同一用户池，通过 `TenantId` 区分 | 同一用户池，通过 `TenantId` 区分 |

### 1.2 各系统调用方式

| 调用方 | 调用 Identity 的内容 | 租户 |
|--------|---------------------|------|
| Admin 项目 | OAuth 授权码流程登录 + 用户管理 API | OpenFindBearings |
| Sync 服务 | client_credentials 获取 M2M token | 可选传 realm |
| Mobile App | 公开注册（SignUp + realm）+ 密码流程登录 | 自行传入 realm |
| 其他系统 | 按需调用用户 CRUD API | 各自的 TenantId |

### 1.3 不负责

各业务系统的细粒度 RBAC（角色-权限映射由各系统自行维护）。

---

## 2. 租户隔离体系

### 2.1 租户解析

Identity 后端**同时支持**两种方式标识租户，**两者均为空时请求被拒绝**（400）：

```
1. realm=租户名称（字符串）  → 查询 Tenants 表按 Name 匹配（推荐，各接入系统默认使用）
2. tenant_id=GUID           → 直接匹配 Tenant.Id（兼容 Keycloak 迁移场景）
```

解析优先级：`tenant_id` 优先于 `realm`（当两者同时传入时以 `tenant_id` 为准）。

`ResolveRequestTenantAsync`（AuthorizationController）和 `ResolveTenantIdAsync`（LoginController）封装此逻辑。

各接入系统（Admin、Mobile App、Sync）**默认优先使用 `realm`**，如：

```
&realm=openfindbearings
```

仅在需要精确 GUID 兼容的场景下使用 `tenant_id`。Identity 后端对两种方式无差别处理。

### 2.2 预置租户

| 租户 | GUID | Realm | 用途 |
|------|------|-------|------|
| 系统租户 | `00000000-0000-0000-0000-000000000000` | `system` | Identity 自管理后台 |
| OpenFindBearings | `00000000-0000-0000-0000-000000000001` | `openfindbearings` | Admin/App/Sync 业务 |

### 2.3 Cookie 隔离

| Cookie | 名称 | 用途 | 写入方式 |
|--------|------|------|----------|
| Identity.Application | `.AspNetCore.Cookies` | OAuth 流程 | `SignInManager.SignInAsync()` |
| Identity.Management | `.AspNetCore.Identity.Management` | 自管理 | `HttpContext.SignInAsync("Identity.Management")` |

`LoginSubmit` 通过 `returnUrl` 分流：以 `/connect/authorize` 开头则写 Application cookie，否则写 Management cookie。

两 cookie 同域共存，互不覆盖。退出端点各清各的。

### 2.4 认证方案绑定

| 控制器集合 | 认证方案 | 说明 |
|-----------|---------|------|
| Home/Users/Tenant/Application/Scope/ProfileController | `Identity.Management` | `[Authorize(AuthenticationSchemes = "Identity.Management")]` |
| AuthorizationController（Authorize 端点） | `IdentityConstants.ApplicationScheme` | 显式调用 `AuthenticateAsync` |
| AccountController | `Bearer` | `[Authorize(AuthenticationSchemes = "Bearer")]` |

---

## 3. OIDC 端点租户校验

### 3.1 端点到租户校验映射

| 端点 | 路径 | 校验方式 |
|------|------|----------|
| Authorize | GET `/connect/authorize` | 已认证用户的 TenantId vs 请求 realm/tenant_id，不匹配则 Challenge 登录页 |
| Token (authorization_code) | POST `/connect/token` | 授权码签发时校验用户 TenantId；交换令牌时二次校验 |
| Token (password) | POST `/connect/token` | `GetByUsernameAsync(username, tenantId)` 租户限定查询 |
| Token (refresh_token) | POST `/connect/token` | 解析请求 tenant_id/realm，与用户 `user.TenantId` 比对 |
| Token (client_credentials) | POST `/connect/token` | 将请求中的 realm/tenant_id 写入 JWT `tenant_id` claim |
| UserInfo | GET `/connect/userinfo` | 从 access_token 的 `tenant_id` claim 与用户 `TenantId` 比对 |
| Logout | GET/POST `/connect/logout` | 仅清 Identity.Application cookie，`post_logout_redirect_uri` 仅允许相对路径 |

### 3.2 刷新令牌租户校验

```
请求参数中的 realm/tenant_id → 与用户当前 TenantId 比对
不匹配 → 返回 403 Forbid（InvalidGrant）
```

### 3.3 客户端凭证租户注入

M2M 服务通过 `client_credentials` 获取令牌时，可在请求中传 realm 或 tenant_id，Identity 将其注入 JWT 的 `tenant_id` claim。下游 API 据此识别 M2M 请求的租户上下文。

---

## 4. Controller 清单

| Controller | 类型 | 路由 | 认证方案 | 职责 |
|-----------|------|------|---------|------|
| AuthorizationController | MVC | `/connect/*` | 内部处理 | OAuth 流程（登录/授权/token/userinfo/logout） |
| LoginController | MVC | `/Account/Login` | `[AllowAnonymous]` | 登录页渲染、登录表单提交 |
| HomeController | MVC | `/Home` | `Identity.Management` | 管理后台首页/仪表盘 |
| UsersController | MVC | `/Users/*` | `Identity.Management` | 用户管理页面（仅系统租户管理员） |
| ApplicationController | MVC | `/Application/*` | `Identity.Management` | OAuth 客户端管理页面 |
| ScopeController | MVC | `/Scope/*` | `Identity.Management` | Scope 管理页面 |
| TenantController | MVC | `/Tenant/*` | `Identity.Management` | 租户管理页面 |
| ProfileController | MVC | `/Profile/*` | `Identity.Management` | 更改密码页面 |
| AccountController | API | `/api/account/*` | `Bearer` | 外部系统调用的用户 CRUD API |
| AuditLogController | API | `/api/auditlog/*` | `Bearer` | 审计日志 API |
| SystemConfigController | API | `/api/systemconfig/*` | `Bearer` | 系统配置 API |

---

## 5. UserService 租户范围

### 5.1 新增租户限定查询

```csharp
// 原方法（跨租户，仅用于注册去重等低风险场景）
Task<UserDto?> GetByUsernameAsync(string username, CancellationToken ct);

// 新增租户限定重载（OAuth 密码流程用）
Task<UserDto?> GetByUsernameAsync(string username, Guid tenantId, CancellationToken ct);
```

实现：

```csharp
var normalizedUsername = username.ToUpperInvariant();
var user = await _userManager.Users
    .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUsername && u.TenantId == tenantId, ct);
```

### 5.2 CreateAsync 强制 TenantId

```csharp
if (request.TenantId == null)
{
    return ServiceResult<UserDto>.Failure(new ServiceError
    {
        Code = "TenantRequired",
        Description = "创建用户时必须指定租户"
    });
}
```

### 5.3 AccountController API 管理端点

- `AdminGetUsers` — 未传 tenantId 时默认从当前管理员 JWT `tenant_id` claim 读取
- `GetTenantUserAsync` — 将管理员的 JWT `tenant_id` 与目标用户的 `TenantId` 比对，不匹配返回 null
- `AdminCreateUser` — TenantId 从管理员 JWT `tenant_id` claim 注入

---

## 6. Login 流程

### 6.1 登录页面

路由：`GET /Account/Login`

从查询参数或 returnUrl 中解析 `realm` 或 `tenant_id`，显示对应的租户名称。

- OAuth 流程：Admin 在授权 URL 中加入 `&realm=openfindbearings`
- 自管理：直接访问 `/` 被 `[Authorize]` 拦截，无 realm 参数，默认显示系统租户

### 6.2 登录提交

路由：`POST /Account/Login`

参数：`username` + `password` + `returnUrl` + `realm`（可选）+ `tenant_id`（可选）

1. `ResolveTenantIdAsync` 解析租户
2. 按 `用户名 + TenantId` 查找用户（复合唯一索引）
3. 校验用户状态和密码
4. 根据 `returnUrl` 分流写入 cookie
5. 重定向到 `returnUrl`

### 6.3 退出

| 场景 | 端点 | 清除的 cookie |
|------|------|--------------|
| 自管理退出 | POST `/Account/Logout` | `Identity.Management` |
| OAuth 退出（Admin 调用） | GET/POST `/connect/logout` | `Identity.Application` |

---

## 7. 公开注册

### 7.1 请求格式

```
POST /api/account/signup
Content-Type: application/json
{
  "account": "string",
  "password": "string",
  "confirmPassword": "string",
  "agreeTerms": true,
  "realm": "openfindbearings"     // 必填，标识租户
}
```

### 7.2 校验

- `realm` 必须对应一个有效的 `Tenant`，否则返回 "Invalid realm"
- `TenantId` 从 realm 解析后传入 `CreateUserDto`
- `CreateAsync` 拒绝 TenantId 为 null 的请求

手机 App 自行硬编码 realm 值（如 "openfindbearings"），不在请求中允许客户端自选。

---

## 8. 客户端与 Scope 管理

### 8.1 客户端清单

| ClientId | 用途 | Grant Type | Scope |
|----------|------|-----------|-------|
| admin_client | Admin 管理后台 | authorization_code | openid profile email roles api:admin |
| sync-client | Sync ETL 服务 | client_credentials | api:sync |
| web-client | Web 客户端 | authorization_code + PKCE | openid profile email roles api:web |
| maui-client | Mobile App | password | api:maui |

### 8.2 Scope 清单

| Scope | 资源 | 说明 |
|-------|------|------|
| api:admin | BaseApi | Admin 管理后台 |
| api:sync | BaseApi | Sync ETL 服务 |
| api:maui | BaseApi | Mobile App |
| api:web | BaseApi | Web 客户端 |

### 8.3 动态管理

Application 和 Scope 通过 Identity MVC 管理页面动态配置，不硬编码在 SeedData 中。SeedData 仅提供初始种子数据。

---

## 9. JWT Token 内容

| 字段 | 来源 | 用途 |
|------|------|------|
| sub (subject) | OidcUser.Id | 用户唯一标识 |
| email | 用户信息 | 基本身份 |
| name | 用户信息 | 显示名称 |
| preferred_username | 用户信息 | 用户名 |
| tenant_id | TenantId | 租户隔离（所有 grant type 均包含） |
| phone_number | 用户信息 | 手机号 |
| given_name / family_name | 用户信息 | 姓名 |
| nickname | 用户信息 | 昵称 |
| gender / birthdate | 用户信息 | 可选信息 |
| locale / zoneinfo | 用户信息 | 本地化信息 |
| scope | 客户端请求 | 标识业务系统（api:admin/api:sync） |
| role | Identity 角色 | 系统级角色（预留） |

---

## 10. 实施状态

| 优先级 | 事项 | 状态 |
|--------|------|------|
| P0 | Controller 重构 | ✅ 完成 |
| P0 | AccountController 拆分 | ✅ 完成 |
| P0 | HomeController | ✅ 完成 |
| P0 | Cookie 隔离：双 cookie 分离 | ✅ 完成 |
| P0 | OIDC 端点租户校验（authorize/token/userinfo/logout） | ✅ 完成 |
| P0 | 管理控制器锁 Identity.Management | ✅ 完成 |
| P1 | 删除冗余角色和 RoleController | ✅ 完成 |
| P1 | AuthorizationController 服务化 | ✅ 完成 |
| P1 | TenantService + TenantController | ✅ 完成 |
| P1 | GetByUsernameAsync 租户限定重载 | ✅ 完成 |
| P1 | CreateAsync 强制 TenantId 非 null | ✅ 完成 |
| P1 | SignUp 加 realm 字段 | ✅ 完成 |
| P1 | Admin API 端点 JWT tenant_id 匹配 | ✅ 完成 |
| P1 | EndSession 开放重定向修复 | ✅ 完成 |
| P2 | MVC View 实现（Application/Scope/User/Tenant/Home） | ✅ 完成 |
| P3 | 审计日志 | ❌ 待处理 |

---

## 11. 端口配置

| 环境 | HTTP | HTTPS | 说明 |
|------|------|-------|------|
| 开发 | 5112 | 7201 | launchSettings.json |
| 生产 | 8080 | — | K3s 容器，Ingress TLS 终止 |

---

## 12. 数据库

### 12.1 表结构

| 表 | 说明 |
|----|------|
| Users | 用户池（含 TenantId，与 NormalizedUserName 组成复合唯一索引） |
| Tenants | 租户表（Name 唯一索引） |
| OpenIddictApplications | OAuth 客户端 |
| OpenIddictScopes | 系统级作用域 |
| OpenIddictAuthorizations | 授权记录 |
| OpenIddictTokens | 令牌记录 |
| AspNetUserRoles | 用户-角色关联 |
| AspNetRoles | 角色定义 |

### 12.2 复合唯一索引

Users 表的 `(NormalizedUserName, TenantId)` 复合唯一索引允许不同租户下有相同用户名。

---

## 13. 安全约束

1. 所有 OIDC 端点（authorize、token、userinfo、logout）均验证 realm/tenant_id
2. 自管理退出仅清 Management cookie，OAuth 退出仅清 Application cookie
3. EndSession 的 `post_logout_redirect_uri` 仅允许相对路径，防止开放重定向
4. `CreateAsync` 拒绝 TenantId 为 null 的请求，防止孤立用户
5. API 管理端点默认从 JWT `tenant_id` claim 读取当前管理员租户
