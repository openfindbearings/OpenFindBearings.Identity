# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.4.0
**日期：** 2026-07-06
**状态：** 与代码同步

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 | 2026-05-07 | 初始版本：用户管理、角色管理、OpenIddict 基础配置 |
| v1.0.1 | 2026-06-01 | 新增 restore 端点 |
| v1.1.0 | 2026-06-12 | 新增 Tenant 基础设施、OIDC 授权端点、登录页 |
| v2.0.0 | 2026-06-12 | Controller 架构重新设计：MVC 自身管理 + API 外部调用分离；清理冗余角色；admin_client scope 改为 api:admin |
| v2.1.0 | 2026-06-15 | 全量实施 MVC 管理页面；TenantService/TenantController；删除 RoleController |
| v2.2.0 | 2026-06-16 | OIDC 全部端点租户校验；UserService 租户范围查询；SignUp 加 realm；开放重定向修复 |
| v2.3.0 | 2026-06-17 | 客户端/Scope/Role 完整租户隔离；OAuth 端点 client_id 和 scope 租户校验；管理 UI 按租户筛选 |
| v2.4.0 | 2026-07-06 | 对齐代码：修正 API 端点表（路由命名、遗漏端点）、Scope 种子数据补充（api:maui、api:web）、SeedData 用户补充（lockeduser） |

---

## 1. 项目定位

OpenFindBearings.Identity 是全局 OIDC 认证中心，同时承载两套独立系统：

### 1.1 两套系统，一个进程

| | 自管理后台 | OIDC 认证服务 |
|---|---|---|
| 用途 | 管理用户/租户/客户端/Scope | 为 Admin/App/Sync 提供 OAuth/OIDC 认证 |
| 入口 | 直接访问 `https://localhost:7201/` | 被 OAuth authorize 重定向 |
| Cookie | `Identity.Application`（`.AspNetCore.Identity.Application`），单 cookie 方案 | 同左（代码级租户隔离） |
| Controller 锁 | `[Authorize]` → DefaultPolicy → `IdentityConstants.ApplicationScheme` | API 端点锁 `[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]` |
| 登录 | POST `/Account/Login`（returnUrl 不含 /connect/authorize） | POST `/Account/Login`（returnUrl 以 /connect/authorize 开头） |
| 退出 | POST `/Account/Logout`（`[IgnoreAntiforgeryToken]` + 直接删 cookie） | GET/POST `/connect/logout`（`_signInManager.SignOutAsync`） |
| 用户池 | 同一用户池，通过 `TenantId` 区分 | 同一用户池，通过 `TenantId` 区分 |

### 1.2 各系统调用方式

| 调用方 | 调用 Identity 的内容 | 租户 |
|--------|---------------------|------|
| Admin 项目 | OAuth 授权码流程登录 + 用户管理 API | OpenFindBearings (realm=openfindbearings) |
| Sync 服务 | client_credentials 获取 M2M token | OpenFindBearings |
| Mobile App | 公开注册（SignUp + realm）+ 密码流程登录 | 自行传入 realm |
| 其他系统 | 按需调用用户 CRUD API | 各自的 TenantId |

### 1.3 不负责

各业务系统的细粒度 RBAC（角色-权限映射由各系统自行维护）。

---

## 2. 租户隔离体系

### 2.1 租户解析

Identity 后端**同时支持**两种方式标识租户，**两者均为空时请求被拒绝**（400）：

```
1. realm=租户名称（字符串） → 查询 Tenants 表按 Name 匹配（推荐，各接入系统默认使用）
2. tenant_id=GUID           → 直接按 Id 匹配（tenant_id 优先级高于 realm）
```

解析中间件 `TenantContextMiddleware` 在请求管道最前端（`UseAuthentication` 前）将 realm 解析为 `TenantInfo` 并缓存到 `HttpContext.Items["TenantInfo"]`。后续 `ITenantResolver.ResolveAsync()` 读取缓存值，无需重复查库。

### 2.2 隔离层级

| 资源 | 隔离方式 | 字段 | 说明 |
|------|---------|------|------|
| 用户 (OidcUser) | 完整隔离 | `TenantId` (Guid?) | 登录时按 TenantId + UserName 复合索引查找 |
| 客户端 (OidcApplication) | 完整隔离 | `TenantId` (Guid?) | 自定义 OpenIddict 实体，创建时绑定租户 |
| Scope (OidcScope) | 完整隔离 | `TenantId` (Guid?) | 自定义 OpenIddict 实体，创建时绑定租户 |
| 角色 (IdentityRole) | 影子属性隔离 | `TenantId` (Guid?, shadow property) | 管理 UI 按租户筛选 |
| 授权 (OidcAuthorization) | 完整隔离 | `TenantId` (Guid?) | OpenIddict 自动按关联客户端/用户验证 |
| 令牌 (OidcToken) | 通过授权链隔离 | 无直接字段 | 令牌通过 Authorization 关联到用户和客户端 |

### 2.3 种子数据

| 客户端 | ClientId | 所属租户 |
|--------|----------|----------|
| 同步服务客户端 | sync-client | OpenFindBearings |
| MAUI 客户端 | maui-client | OpenFindBearings |
| Web 客户端 | web-client | OpenFindBearings |
| Admin 后台管理 | admin_client | OpenFindBearings |

| Scope | 名称 | 所属租户 |
|-------|------|----------|
| Sync API | api:sync | OpenFindBearings |
| Admin API | api:admin | OpenFindBearings |
| MAUI API | api:maui | OpenFindBearings |
| Web API | api:web | OpenFindBearings |

### 2.4 管理 UI 租户过滤

- **系统管理员**（`TenantId = SystemTenantId`）：查看所有租户的客户端/Scope/Role
- **非系统管理员**（`TenantId = OpenFindBearingsTenantId`）：仅查看本租户的客户端/Scope/Role

---

## 3. Cookie 认证方案

使用**单 cookie 方案**：`Identity.Application`（`.AspNetCore.Identity.Application`）。登录统一走 `SignInManager.SignInAsync()`。

隔离通过**代码级 TenantId 判断**，而非分离 cookie scheme。

### 3.1 租户校验时机

所有 OIDC 端点（`connect/authorize`, `connect/token`, `connect/userinfo`, `connect/logout`）均进行租户校验：

```
请求 → TenantContextMiddleware 解析 realm/tenant_id
     → 各 Handler 校验：
         1. client_id 是否属于当前租户（IsClientInTenantAsync）
         2. 自定义 scope 是否属于当前租户（IsScopeInTenantAsync）
         3. 用户 TenantId 是否匹配请求租户
     → 任一步失败返回 400/BadRequest 或 Forbid
```

### 3.2 例外：`connect/revocation`

OpenIddict 内部处理，无需租户校验。

---

## 4. OpenIddict 自定义实体

为了在 OpenIddict 实体上添加 `TenantId` 字段，创建了 4 个自定义实体类，继承 OpenIddict EF Core 基类：

| 实体 | 基类 | 对应表 | 新增字段 |
|------|------|--------|----------|
| `OidcApplication` | `OpenIddictEntityFrameworkCoreApplication<Guid, ...>` | `Clients` | `TenantId` (Guid?) |
| `OidcAuthorization` | `OpenIddictEntityFrameworkCoreAuthorization<Guid, ...>` | `Authorizations` | `TenantId` (Guid?) |
| `OidcScope` | `OpenIddictEntityFrameworkCoreScope<Guid>` | `Scopes` | `TenantId` (Guid?) |
| `OidcToken` | `OpenIddictEntityFrameworkCoreToken<Guid, ...>` | `Tokens` | 无 TenantId（令牌通过授权链隔离） |

---

## 5. 服务层

### 5.1 接口与实现

| 接口 | 实现 | 说明 |
|------|------|------|
| IClientService | ClientService | 客户端 CRUD，租户过滤（GetPagedAsync），租户校验（IsClientInTenantAsync） |
| IScopeService | ScopeService | Scope CRUD，租户过滤（GetPagedAsync/GetAllAsync），租户校验（IsScopeInTenantAsync） |
| IUserService | UserService | 用户 CRUD，租户范围查询（GetByUsernameAsync(username, tenantId)） |
| ITenantService | TenantService | 租户 CRUD |
| ITenantResolver | TenantResolver | 封装 TenantContextMiddleware 解析的租户信息 |
| IAuditLogService | AuditLogService | 审计日志 CRUD |
| ISystemConfigService | SystemConfigService | 系统配置键值存储 |

### 5.2 客户端/Scope 租户筛选

`GetPagedAsync(search, tenantId)` 扩展参数：
- `tenantId = null`：系统管理员，返回全部
- `tenantId = specific`：仅返回匹配该租户的客户端/Scope

在 `IOpenIddictApplicationManager.ListAsync()` 枚举过程中，通过 `scope is OidcApplication oa` 判断并过滤。

---

## 6. API 端点

AccountController（`/api/account`）的 API 端点：

| 方法 | 路由 | 用途 | 认证 |
|------|------|------|------|
| POST | `/api/account/signup` | 用户注册 | 匿名 |
| GET | `/api/account/me` | 当前用户信息 | OpenIddict Bearer |
| PUT | `/api/account/me/profile` | 更新当前用户资料 | OpenIddict Bearer |
| POST | `/api/account/me/change-password` | 修改密码 | OpenIddict Bearer |
| DELETE | `/api/account/me/account` | 删除当前账户（软删除） | OpenIddict Bearer |
| GET | `/api/account/admin/users` | 分页获取用户列表（管理员） | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/account/admin/users/{id}` | 获取用户详情（管理员） | OpenIddict Bearer + SuperAdmin/Admin |
| POST | `/api/account/admin/users` | 创建用户（管理员） | OpenIddict Bearer + SuperAdmin/Admin |
| PUT | `/api/account/admin/users/{id}` | 更新用户（管理员） | OpenIddict Bearer + SuperAdmin/Admin |
| DELETE | `/api/account/admin/users/{id}` | 删除用户（管理员，软删除） | OpenIddict Bearer + SuperAdmin/Admin |
| PATCH | `/api/account/admin/users/{id}/status` | 启用/禁用用户 | OpenIddict Bearer + SuperAdmin/Admin |
| POST | `/api/account/admin/users/{id}/unlock` | 解锁用户 | OpenIddict Bearer + SuperAdmin/Admin |
| POST | `/api/account/admin/users/{id}/reset-password` | 重置用户密码 | OpenIddict Bearer + SuperAdmin/Admin |
| POST | `/api/account/admin/users/{id}/restore` | 恢复已删除用户 | OpenIddict Bearer + SuperAdmin/Admin |

AuditLogController（`/api/auditlog`）的管理端点：

| 方法 | 路由 | 用途 | 认证 |
|------|------|------|------|
| GET | `/api/auditlog` | 分页获取审计日志 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/auditlog/{id:guid}` | 获取日志详情 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/auditlog/today-count` | 获取今日日志数量 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/auditlog/recent` | 获取最近操作日志 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/auditlog/user/{userId:guid}` | 获取指定用户日志 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/auditlog/statistics/actions` | 获取操作类型统计 | OpenIddict Bearer + SuperAdmin/Admin |

SystemConfigController（`/api/systemconfig`）的管理端点：

| 方法 | 路由 | 用途 | 认证 |
|------|------|------|------|
| GET | `/api/systemconfig` | 分页获取配置列表 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/systemconfig/dictionary` | 获取全部配置（字典格式） | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/systemconfig/{key}` | 按键获取配置值 | OpenIddict Bearer + SuperAdmin/Admin |
| GET | `/api/systemconfig/{key}/object` | 按键获取配置对象 | OpenIddict Bearer + SuperAdmin/Admin |
| PUT | `/api/systemconfig/{key}` | 创建或更新配置 | OpenIddict Bearer + SuperAdmin/Admin |
| DELETE | `/api/systemconfig/{key}` | 删除配置 | OpenIddict Bearer + SuperAdmin/Admin |
| PATCH | `/api/systemconfig/{key}/description` | 更新配置描述 | OpenIddict Bearer + SuperAdmin/Admin |

---

## 7. 项目结构

```
src/OpenFindBearings.Identity/
├── Controllers/
│   ├── AccountController.cs        # API: 用户 CRUD + 注册（JWT Bearer）
│   ├── ApplicationController.cs    # MVC: 客户端管理
│   ├── AuditLogController.cs       # API: 审计日志
│   ├── AuthorizationController.cs  # OAuth 端点 (authorize/token/userinfo/logout)
│   ├── HomeController.cs           # MVC: 仪表盘
│   ├── LoginController.cs          # MVC: 登录
│   ├── ProfileController.cs        # MVC: 更改密码
│   ├── ScopeController.cs          # MVC: Scope 管理
│   ├── TenantController.cs         # MVC: 租户管理
│   └── UsersController.cs          # MVC: 用户管理
├── Data/
│   ├── ApplicationDbContext.cs     # EF Core DbContext
│   ├── SeedData.cs                 # 种子数据
│   └── Migrations/                 # EF Core 迁移
├── Extensions/
│   └── ServiceExtensions.cs        # DI 注册 + 中间件管道
├── Middleware/
│   └── TenantContextMiddleware.cs  # 租户解析中间件
├── Models/
│   ├── DTOs/                       # 数据传输对象
│   │   ├── AuditLog/
│   │   ├── SystemConfig/
│   │   ├── User/
│   │   └── ...
│   ├── Entities/                   # 领域实体
│   │   ├── OidcUser.cs
│   │   ├── Tenant.cs
│   │   └── OpenIddict/             # 自定义 OpenIddict 实体
│   │       ├── OidcApplication.cs
│   │       ├── OidcAuthorization.cs
│   │       ├── OidcScope.cs
│   │       └── OidcToken.cs
│   ├── Requests/                   # 请求 DTO
│   │   ├── SignUpRequest.cs        # 含 InviteCode 字段
│   │   ├── AdminCreateUserRequest.cs
│   │   └── ...
│   ├── Responses/                  # 响应 DTO
│   └── ValueObjects/              # 值对象（Address）
├── Services/
│   ├── ClientService.cs
│   ├── ScopeService.cs
│   ├── UserService.cs
│   ├── TenantService.cs
│   ├── TenantResolver.cs
│   ├── AuditLogService.cs
│   └── SystemConfigService.cs
├── Constants/
│   └── TenantConstants.cs          # 租户常量
├── Views/                          # MVC 视图
│   ├── Home/
│   ├── Users/
│   ├── Application/
│   ├── Scope/
│   ├── Tenant/
│   ├── Login/
│   └── Profile/
└── Program.cs
```

---

## 8. 种子数据

启动时 `SeedData.SeedAsync()` 依次执行：

1. **Tenants**：SystemTenant + OpenFindBearingsTenant（idempotent）
2. **Roles**：SuperAdmin, Admin, User, TestUser（idempotent）
3. **Users**：7 个用户（2 admin + 5 测试用户，含 lockeduser）（idempotent，按 TenantId + UserName 唯一性）
4. **UserRoles**：管理员配 SuperAdmin+Admin，其余配 User（idempotent）
5. **Clients**：sync-client / maui-client / web-client / admin_client（创建后绑定到 OpenFindBearings 租户）
6. **Scopes**：api:sync / api:admin / api:maui / api:web（创建后绑定到 OpenFindBearings 租户）

---

## 9. 部署

- 端口：HTTP=5112, HTTPS=7201
- 数据库：PostgreSQL `db_identity`
- Data Protection：仅用于 HTTPS，无持久化（开发环境每次重启需重新登录）
- 证书：开发环境使用 `.AddDevelopmentEncryptionCertificate()` + `.AddDevelopmentSigningCertificate()`
