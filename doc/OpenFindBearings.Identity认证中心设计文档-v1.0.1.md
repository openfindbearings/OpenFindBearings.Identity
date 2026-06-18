# OpenFindBearings.Identity 认证中心 v1.0.0

## 概述

OpenFindBearings.Identity 是基于 ASP.NET Identity + OpenIddict 7.5 的统一认证授权中心。提供 OAuth 2.0 / OpenID Connect 认证、用户管理、角色管理、客户端管理和审计日志功能。

所有项目通过 Identity 集中认证，Admin 后台也通过接入 OpenIddict 统一管理用户权限。

## 技术栈

| 层面 | 技术 |
|------|------|
| 框架 | .NET 10, ASP.NET Core |
| 认证 | ASP.NET Identity + OpenIddict 7.5 |
| 数据库 | PostgreSQL (Npgsql + EF Core) |
| 密码哈希 | `IPasswordHasher<OidcUser>` |
| Token 清理 | OpenIddict.Quartz |
| 健康检查 | `AddDbContextCheck` + Memory/Disk 自定义检查 |
| 部署端口 | HTTP 5112, HTTPS 7201 (开发) |

## 项目结构

```
OpenFindBearings.Identity/
├── Program.cs
├── Constants/
│   ├── ApiResourceConstants.cs
│   ├── DeviceTypeConstants.cs
│   ├── GrantTypeConstants.cs
│   └── SmsCodeTypeConstants.cs
├── Controllers/
│   ├── AccountController.cs        — 用户注册/登录/管理
│   ├── ApplicationController.cs    — OAuth 客户端 CRUD
│   ├── AuditLogController.cs       — 审计日志查询
│   ├── AuthorizationController.cs  — OAuth2 令牌端点
│   ├── RoleController.cs           — 角色 CRUD
│   ├── ScopeController.cs          — OAuth Scope CRUD
│   └── SystemConfigController.cs   — 系统配置
├── Data/
│   ├── ApplicationDbContext.cs
│   ├── SeedData.cs                 — 种子用户/角色/客户端
│   └── Repositories/
├── Models/
│   ├── Entities/                   — OidcUser, AuditLog, SmsCode, SystemConfig
│   ├── Enums/                      — LoginProviders, UserStatusFilter
│   ├── DTOs/                       — UserDto, RoleDto, ClientDto 等
│   ├── Requests/                   — 请求 DTO (15 个)
│   ├── Responses/                  — ApiResponse, LoginResponse, UserResponse
│   └── ValueObjects/               — Address
├── Services/                       — UserService, ClientService, RoleService 等
├── Extensions/                     — 服务注册扩展, Mapping 扩展
├── Helpers/                        — ApiResponseHelper, EmailHelper 等
└── Properties/
    └── launchSettings.json
```

## OpenIddict 配置

### 端点

| 端点 | URI | 用途 |
|------|-----|------|
| 授权 | `/connect/authorize` | OAuth2 授权 |
| 令牌 | `/connect/token` | 颁发/刷新令牌 |
| 用户信息 | `/connect/userinfo` | 当前用户信息 |
| 退出 | `/connect/logout` | 退出登录 |
| 撤销 | `/connect/revocation` | 令牌撤销 |

### 启用的授权类型

| 授权类型 | 说明 |
|---------|------|
| `password` | 用户名+密码登录 |
| `client_credentials` | 客户端凭证（M2M 场景） |
| `refresh_token` | 令牌自动刷新 |
| `authorization_code` | 授权码流程（Web 应用） |

### Scope

| Scope | 说明 |
|-------|------|
| `openid` | OpenID Connect 标准 |
| `profile` | 用户资料 |
| `email` | 邮箱 |
| `roles` | 角色 |
| `phone` | 手机号 |
| `address` | 地址 |
| `api:sync` | Sync M2M 专用 |

### 客户端注册

| 客户端 ID | 类型 | 授权类型 | 用途 |
|-----------|------|---------|------|
| `sync-client` | 机密 | client_credentials + refresh_token | Sync ETL M2M |
| `maui-client` | 公开 | password + refresh_token | 移动端 |
| `web-client` | 机密 | authorization_code + refresh_token + PKCE | 前端 Web |
| `admin_client` | 机密 | authorization_code + refresh_token + PKCE | Admin 后台 |

### 令牌生命周期

| 令牌 | 有效期 |
|------|--------|
| 访问令牌 | 10 分钟 |
| 刷新令牌 | 30 天（绝对） |

## 数据库 Schema

### Users（OidcUser = IdentityUser<Guid> 扩展）

| 列 | 类型 | 说明 |
|----|------|------|
| Id | uuid PK | |
| UserName | varchar(256) | 唯一索引 |
| Email | varchar(256) | |
| PhoneNumber | text | |
| PasswordHash | text | BCrypt |
| IsEnabled | bool | 启用/禁用 |
| IsActive | bool | 软删除 |
| LastLoginAt | timestamptz | 最后登录时间 |
| Name, GivenName, FamilyName | text | OIDC 标准字段 |
| Nickname, ProfileUrl, PictureUrl | text | OIDC 标准字段 |
| Gender, Birthdate, Locale, ZoneInfo | text | OIDC 标准字段 |
| Address | JSON | 地址值对象 |
| CreatedAt, UpdatedAt, DeletedAt | timestamptz | 审计字段 |

### Roles（IdentityRole<Guid>）

| 列 | 类型 |
|----|------|
| Id | uuid PK |
| Name | varchar(256) |
| NormalizedName | varchar(256) 唯一索引 |

### UserRoles（多对多关联）

| 列 | 类型 |
|----|------|
| UserId | uuid FK → Users |
| RoleId | uuid FK → Roles |

### AuditLogs

| 列 | 类型 | 说明 |
|----|------|------|
| Id | uuid PK | |
| UserId | uuid? | 操作人 |
| Username | text | 用户名 |
| Action | varchar(100) | 操作类型（Login/Logout/CreateUser/DeleteRole 等） |
| ResourceType | varchar(50) | 资源类型（User/Role/Client/Scope） |
| ResourceId | text | 资源 ID |
| Details | text | 详细信息（JSON） |
| Status | varchar(20) | Success/Failure |
| FailureReason | text | 失败原因 |
| ClientId | text | 客户端 ID |
| IpAddress | varchar(45) | IP 地址 |
| UserAgent | text | |
| CreatedAt | timestamptz | 创建时间 |

### SystemConfigs

| 列 | 类型 | 说明 |
|----|------|------|
| Id | uuid PK | |
| Key | varchar(200) | 唯一 |
| Value | text | JSON 值 |
| Description | varchar(500) | 描述 |
| CreatedAt | timestamptz | |
| UpdatedAt | timestamptz? | |

### SmsCodes

| 列 | 类型 | 说明 |
|----|------|------|
| Id | uuid PK | |
| PhoneNumber | varchar(20) | 手机号 |
| Code | varchar(10) | 验证码 |
| Type | varchar(50) | 类型 |
| IsUsed | bool | 是否已用 |
| ExpiresAt | timestamptz | 过期时间 |
| AttemptCount | int | 尝试次数（上限后过期） |

### OpenIddict 内部表

Clients / Scopes / Authorizations / Tokens — OpenIddict 标准 schema。

## API 端点清单

### 1. 账号管理 — `/api/account`

#### 公开

| 方法 | 路径 | 说明 | 参数 |
|------|------|------|------|
| POST | `/api/account/signup` | 用户注册 | `SignUpRequest`：Account, Password, ConfirmPassword, InviteCode?, AgreeTerms |

#### 用户自身（需认证）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/account/me` | 获取个人资料 |
| PUT | `/api/account/me/profile` | 更新个人资料 |
| POST | `/api/account/me/change-password` | 修改密码 |
| DELETE | `/api/account/me/account` | 注销账户 |

#### 管理员（需 SuperAdmin/Admin 角色）

| 方法 | 路径 | 说明 | 备注 |
|------|------|------|------|
| GET | `/api/account/admin/users` | 用户列表（分页+搜索+筛选项） | |
| GET | `/api/account/admin/users/{id}` | 用户详情 | |
| POST | `/api/account/admin/users` | 创建用户（指定用户名/邮箱/密码/角色） | |
| PUT | `/api/account/admin/users/{id}` | 更新用户（含角色） | |
| DELETE | `/api/account/admin/users/{id}` | 软删除用户 | |
| PATCH | `/api/account/admin/users/{id}/status` | 启用/禁用用户 | |
| POST | `/api/account/admin/users/{id}/unlock` | 解锁用户 | |
| POST | `/api/account/admin/users/{id}/reset-password` | 重置密码 | |
| POST | `/api/account/admin/users/{id}/restore` | 恢复已软删除的用户 | `UserService.RestoreAsync()` 已实现，控制器已添加 |

**用户列表筛选参数**：
- `Page`, `PageSize`
- `Search` — 用户名/邮箱/手机号模糊搜索
- `Status` — All / Enabled / Disabled / Locked
- `Role` — 按角色过滤
- `DateFrom`, `DateTo` — 创建时间范围
- `LastLoginFrom`, `LastLoginTo` — 最后登录时间范围

### 2. OAuth 令牌 — `~/connect/token`

| 方法 | 类型 | 说明 |
|------|------|------|
| POST | password | 用户名+密码登录 |
| POST | client_credentials | 客户端凭证 |
| POST | refresh_token | 刷新令牌 |

返回：`access_token`, `token_type` (Bearer), `expires_in`, `refresh_token`, `user`

### 3. OAuth 客户端管理 — `/api/application`（需 SuperAdmin/Admin）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/application/` | 客户端列表（分页+搜索） |
| GET | `/api/application/{clientId}` | 客户端详情 |
| POST | `/api/application/` | 创建客户端 |
| PUT | `/api/application/{clientId}` | 更新客户端信息 |
| DELETE | `/api/application/{clientId}` | 删除客户端 |
| POST | `/api/application/{clientId}/regenerate-secret` | 重新生成客户端密钥 |

### 4. 角色管理 — `/api/role`（需 SuperAdmin/Admin）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/role/` | 角色列表（分页+搜索） |
| GET | `/api/role/all` | 所有角色 |
| GET | `/api/role/{id}` | 角色详情 |
| GET | `/api/role/by-name/{name}` | 按名称查询 |
| POST | `/api/role/` | 创建角色 |
| DELETE | `/api/role/{id}` | 删除角色（有用户的角色不可删除） |

### 5. Scope 管理 — `/api/scope`（需 SuperAdmin/Admin）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/scope/` | Scope 列表 |
| GET | `/api/scope/all` | 所有 Scope |
| GET | `/api/scope/{name}` | 按名称查询 |
| POST | `/api/scope/` | 创建 Scope |
| PUT | `/api/scope/{name}` | 更新 Scope |
| DELETE | `/api/scope/{name}` | 删除 Scope（标准 scope 不可删除） |

### 6. 审计日志 — `/api/auditlog`（需 SuperAdmin/Admin）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/auditlog/` | 审计日志列表（分页+筛选） |
| GET | `/api/auditlog/{id}` | 日志详情 |
| GET | `/api/auditlog/today-count` | 今日日志数 |
| GET | `/api/auditlog/recent` | 最近日志 |
| GET | `/api/auditlog/user/{userId}` | 指定用户的操作记录 |
| GET | `/api/auditlog/statistics/actions` | 操作类型统计 |

### 7. 系统配置 — `/api/systemconfig`（需 SuperAdmin/Admin）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/systemconfig/` | 配置列表 |
| GET | `/api/systemconfig/dictionary` | 所有配置（键值对字典） |
| GET | `/api/systemconfig/{key}` | 按 key 获取 |
| GET | `/api/systemconfig/{key}/object` | 按 key 获取（解析为对象） |
| PUT | `/api/systemconfig/{key}` | 设置配置值 |
| DELETE | `/api/systemconfig/{key}` | 删除配置 |
| PATCH | `/api/systemconfig/{key}/description` | 更新描述 |

### 8. 健康检查

| 路径 | 用途 |
|------|------|
| `/live` | 存活探针（无检查） |
| `/ready` | 就绪探针（排除 `startup` 标签） |
| `/health` | 详细健康报告 |
| `/healthz` | 简化健康检查 |

## 种子数据

### 预置角色

| 名称 | 说明 |
|------|------|
| SuperAdmin | 超级管理员 |
| Admin | 管理员 |
| User | 普通用户 |
| TestUser | 测试用户 |

### 预置用户

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | Admin@123456 | SuperAdmin, Admin |
| zhangsan | User@123456 | User |
| lisi | User@123456 | User |
| wangwu | User@123456 | User |
| lockeduser | Locked@123456 | User（已禁用+锁定） |
| testuser | Test@123456 | TestUser |

### 预置 OAuth 客户端

| 客户端 ID | 密钥 | 类型 | 用途 |
|-----------|------|------|------|
| sync-client | 388D45FA-B36B-4988-BA59-B187D329C207 | 机密 | Sync ETL |
| maui-client | 无 | 公开 | 移动端 |
| web-client | web-secret-123 | 机密 | Web 前端 |
| admin_client | 需创建 | 机密 | Admin 后台 |

## 审计日志

Identity 自带完整的审计日志功能。所有管理员操作都会记录到 `AuditLogs` 表：

| 操作类型 | 触发场景 |
|---------|---------|
| Login | 用户登录 |
| Logout | 用户退出 |
| CreateUser | 管理员创建用户 |
| UpdateUser | 管理员更新用户 |
| DeleteUser | 管理员删除用户 |
| ToggleUserStatus | 启用/禁用用户 |
| ResetPassword | 重置用户密码 |
| UnlockUser | 解锁用户 |
| CreateRole | 创建角色 |
| DeleteRole | 删除角色 |
| CreateClient | 创建 OAuth 客户端 |
| UpdateClient | 更新客户端 |
| DeleteClient | 删除客户端 |
| RegenerateSecret | 重新生成密钥 |
| CreateScope | 创建 Scope |
| UpdateScope | 更新 Scope |
| DeleteScope | 删除 Scope |
| UpdateSystemConfig | 更新配置 |

## Admin 集成要点

Identity 当前已具备 Admin 所需的全部认证和用户管理能力：

1. **认证流程**：Admin 作为 confidential client，走 authorization_code + PKCE 流程
2. **用户管理**：通过 AccountController 的 `admin/users/*` 端点完全覆盖
3. **角色管理**：通过 RoleController 管理角色
4. **审计日志**：Identity 自己的 AuditLog 已记录认证相关操作
5. **系统配置**：可通过 SystemConfigController 管理全局配置

### 集成清单

| 功能 | Admin 如何调用 | Identity 端点 |
|------|---------------|---------------|
| 登录 | 跳转 OAuth 授权 | `~/connect/authorize` + `~/connect/token` |
| 获取用户列表 | GET 请求 | `GET /api/account/admin/users` |
| 创建用户 | POST 请求 | `POST /api/account/admin/users` |
| 禁用用户 | PATCH 请求 | `PATCH /api/account/admin/users/{id}/status` |
| 重置密码 | POST 请求 | `POST /api/account/admin/users/{id}/reset-password` |
| 恢复用户 | POST 请求（需自行实现） | `POST /api/account/admin/users/{id}/restore` |
| 角色列表 | GET 请求 | `GET /api/role/all` |
| 创建角色 | POST 请求 | `POST /api/role/` |
| OAuth 客户端列表 | GET 请求 | `GET /api/application/` |
| 查看审计日志 | GET 请求 | `GET /api/auditlog/` |

### 需要做的配置

在 Identity 的种子数据中注册 Admin 客户端（`SeedData.cs` 中已实现 `admin_client` 注册）：

```csharp
// SeedClientsAsync 中已添加以下代码
if (await appManager.FindByClientIdAsync("admin_client") == null)
{
    await appManager.CreateAsync(new OpenIddictApplicationDescriptor
    {
        ClientId = "admin_client",
        ClientSecret = "admin-secret-key",
        ClientType = ClientTypes.Confidential,
        DisplayName = "Admin后台管理",
        ...
    });
}
```

在生产环境部署时，根据实际域名修改 `RedirectUris` 和 `PostLogoutRedirectUris`。

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0.0 | 2026-06-08 | 初始文档 |
| v1.0.1 | 2026-06-09 | restore 端点标注更新为"控制器已添加"；补充 Admin 集成清单；补充 admin_client 种子代码；补充审计日志表完整列定义；补充还原端点说明 |
