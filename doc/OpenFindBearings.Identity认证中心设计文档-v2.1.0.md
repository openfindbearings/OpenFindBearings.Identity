# OpenFindBearings.Identity 认证中心设计文档

**版本：** v2.1.0  
**日期：** 2026-06-15  
**状态：** 已实施（MVC 管理页面完成）

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 | 2026-05-07 | 初始版本：用户管理、角色管理、OpenIddict 基础配置 |
| v1.0.1 | 2026-06-01 | 新增 restore 端点 |
| v1.1.0 | 2026-06-12 | 新增 Tenant 基础设施、OIDC 授权端点、登录页 |
| v2.0.0 | 2026-06-12 | Controller 架构重新设计：MVC 自身管理 + API 外部调用分离；清理冗余角色；admin_client scope 改为 api:admin |
| v2.1.0 | 2026-06-15 | 全量实施 MVC 管理页面：HomeController 仪表盘、UsersController 用户管理、ApplicationController/ScopeController API→MVC 转换、TenantController 租户管理（含 ITenantService/TenantService/DTO）；删除 RoleController（ASP.NET Identity 角色未使用）；_Layout.cshtml 重写为侧边栏布局 |

---

## 1. 项目定位

OpenFindBearings.Identity 是全局 OIDC 认证中心，负责：

1. **OAuth2/OIDC 认证服务** — 授权码流程、令牌签发、用户信息
2. **用户池管理** — 身份信息的唯一数据源
3. **OAuth 基础设施管理** — Application（客户端）和 Scope（系统级作用域）的动态配置

**不负责**各业务系统的细粒度 RBAC（角色-权限映射由各系统自行维护）。

### 1.1 与其他项目的关系

```
Identity 认证中心（MVC + API 混合）
│
├── OAuth 端点（公开）
│   ├── /connect/authorize → 授权码流程
│   ├── /connect/token → 令牌签发
│   └── /connect/userinfo → 用户信息
│
├── MVC 管理页面（Identity 自身管理，需登录）
│   ├── 首页/仪表盘
│   ├── Application 管理（OAuth 客户端）
│   ├── Scope 管理（系统级作用域）
│   └── 用户管理（用户池维护）
│
└── API 端点（供外部系统调用）
    └── /api/users/* → 用户 CRUD（Admin/Sync 等系统调用）
```

### 1.2 各系统调用方式

| 调用方 | 调用 Identity 的内容 | TenantId |
|--------|---------------------|----------|
| Admin 项目 | 调用户 API 创建/查询用户 | OpenFindBearings 固定值 |
| Sync/其他系统 | 调用户 API 创建/查询用户 | 各自系统的固定值 |
| Admin 项目 | OAuth 授权码流程登录 | — |
| 业务系统 | JWT 验证 + scope 识别 | token 中的 tenant_id |

---

## 2. Controller 架构重新设计

### 2.1 当前问题

| 问题 | 说明 |
|------|------|
| 所有 Controller 都是 API Controller | ApplicationController/ScopeController/RoleController 等应为 MVC Controller（带 View 页面），用于 Identity 自身管理 |
| AccountController 职责混合 | 同时承担外部系统 API 调用和自身用户管理 |
| Identity 角色（SuperAdmin/Admin/User）未使用 | 模板遗留，OpenFindBearings 业务系统不用这些角色 |
| AuthorizationController 使用封装 Service | 应直接使用 UserManager/OpenIddictManager，保持与 SeedData 一致 |

### 2.2 重构后 Controller 清单

| Controller | 类型 | 路由 | 职责 |
|-----------|------|------|------|
| AuthorizationController | MVC | `/connect/*` + `/Authorization/*` | OAuth 流程（登录/授权/token） |
| HomeController | MVC | `/Home` | Identity 管理后台首页/仪表盘 |
| UsersController | MVC | `/Users/*` | Identity 自身用户管理页面（列表/创建/删除/重置密码） |
| ApplicationController | MVC | `/Application/*` | Identity 自身客户端管理页面（列表/创建/编辑/删除/重新生成密钥） |
| ScopeController | MVC | `/Scope/*` | Identity 自身 Scope 管理页面（列表/创建/编辑/删除） |
| TenantController | MVC | `/Tenant/*` | 租户管理页面（列表/创建/编辑/删除） |
| AccountController | API | `/api/account/*` | 供外部系统调用的用户 CRUD API（保持不变） |
| AuditLogController | API | `/api/auditlog/*` | 审计日志 API（供 Admin 调用） |
| ProfileController | MVC | `/Profile/*` | 更改密码页面 |
| SystemConfigController | API | `/api/systemconfig/*` | 系统配置 API |

> RoleController（API）已删除——ASP.NET Identity 角色（SuperAdmin/Admin/User/TestUser）在 OpenFindBearings 系统中未使用。

### 2.3 MVC Controller 设计要点

- 继承 `Controller`（不是 `ControllerBase`）
- 不加 `[ApiController]` 特性
- 返回 View（Razor 视图）
- 用 `[Authorize]` 保护（ASP.NET Cookie 认证）
- 不使用 Identity 角色（SuperAdmin/Admin）——管理页面访问控制通过 Cookie 认证即可

### 2.4 API Controller 设计要点

- 继承 `ControllerBase`
- 加 `[ApiController]` 特性
- 返回 JSON
- 用 JWT Bearer 认证（供外部系统调用）
- 不使用 `[Authorize(Roles = "...")]`——外部系统通过 scope 或权限过滤器控制访问

---

## 3. 登录页共用

### 3.1 两种登录场景

| 场景 | 入口 | 登录后跳转 |
|------|------|-----------|
| OAuth 授权码流程 | `AuthorizationController.Login?returnUrl=...` | 跳回 `/connect/authorize`（带 code） |
| Identity 自身管理登录 | 访问 `/Home` 等 MVC 页面，被 `[Authorize]` 拦截 | 跳回原始请求页面 |

### 3.2 实现方式

- Login 页面统一入口（`/Authorization/Login`）
- 通过 `returnUrl` 参数区分场景：
  - 有 `returnUrl`（OAuth 流程）→ 登录后跳转到 `returnUrl`
  - 无 `returnUrl`（管理页面）→ 登录后跳转到 `/Home`
- Cookie 认证配置 `LoginPath = "/Authorization/Login"` 自动拦截未认证请求
- ASP.NET 认证中间件自动将原始请求 URL 编码到返回 URL 中

### 3.3 Views 复用

两套场景共享同一套 Views：
- `Views/Shared/_Layout.cshtml` — 登录页专用布局（现代感设计，独立于 Admin 风格）
- `Views/Authorization/Login.cshtml` — 登录表单

---

## 4. RBAC 架构

### 4.1 职责划分

```
Identity（系统级）
├── scope: api:admin / api:sync / api:mobile
├── tenant_id: 标识用户归属的业务系统
└── 不管理业务级角色和权限

Admin 项目（业务级）
├── admin_role_permissions 表（自定义角色 + 17 个权限键）
├── PermissionKey 枚举（bearing.view / bearing.create / ...）
└── PermissionEndpointFilter 门控

其他业务系统（各自维护）
└── 自行管理角色-权限映射
```

### 4.2 JWT Token 内容

| 字段 | 来源 | 用途 |
|------|------|------|
| sub | OIDC 标准 | 用户 ID |
| email | 用户信息 | 基本身份 |
| name | 用户信息 | 显示名称 |
| tenant_id | SeedData 配置 | 租户隔离 |
| scope | 客户端请求 | 标识业务系统（api:admin/api:sync） |
| role | Identity 角色 | 系统级角色（预留，当前未使用） |

### 4.3 为什么不在 Token 中放业务权限

- 权限变动频繁，JWT 中期无法撤销
- 各系统权限结构不同，放进去 Token 会膨胀
- `IPermissionService` 在每个请求时查本地库更灵活
- Token 只承载身份认证信息，业务授权由各系统自行处理

---

## 5. 客户端与 Scope 管理

### 5.1 客户端清单

| ClientId | 用途 | ConsentType | Scope |
|----------|------|-------------|-------|
| admin_client | Identity 自身管理 Web | Implicit | openid profile email roles api:admin |
| web_client | Admin 项目管理后台 | Implicit | openid profile email roles api:admin |
| api:sync_client | Sync ETL 服务 | Implicit | openid api:sync |
| api:mobile_client | Mobile App | Implicit | openid api:mobile |

### 5.2 Scope 清单

| Scope | 资源 | 说明 |
|-------|------|------|
| api:admin | BaseApi | Admin 管理后台 |
| api:sync | BaseApi | Sync ETL 服务 |
| api:mobile | BaseApi | Mobile App |

### 5.3 动态管理

Application 和 Scope 通过 Identity MVC 管理页面动态配置，不硬编码在 SeedData 中。SeedData 仅提供初始种子数据。

---

## 6. 多租户架构

### 6.1 Tenant 实体

```csharp
public class Tenant
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
}
```

### 6.2 OidcUser TenantId

```csharp
public Guid TenantId { get; set; }  // 非空，FK → Tenant
```

### 6.3 种子数据

- Tenant：OpenFindBearings（固定 GUID）
- 所有种子用户关联到此 TenantId
- 各业务系统创建用户时传入自己的 TenantId

### 6.4 JWT Token 中的 tenant_id

`/connect/token` 端点在签发 token 时加入 `tenant_id` claim。业务系统通过 `ICurrentUserService.TenantId` 读取。

### 6.5 Tenant 服务层

遵循 Controller 统一调用封装 Service 的原则，Tenant 拥有独立的服务层：

```csharp
public interface ITenantService
{
    Task<PaginatedResult<TenantDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default);
    Task<TenantDto?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<ServiceResult<TenantDto>> CreateAsync(CreateTenantDto request, CancellationToken ct = default);
    Task<ServiceResult> UpdateAsync(Guid id, UpdateTenantDto request, CancellationToken ct = default);
    Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default);
}
```

- 实现使用 ApplicationDbContext 直接操作 Tenant 表
- 删除前检查是否有用户关联（防止误删）
- 列表返回携带用户数统计

### 6.6 Tenant 管理页面

| 页面 | 路由 | 功能 |
|------|------|------|
| 列表 | `/Tenant` | 分页、搜索、启用/禁用状态、用户数 |
| 新建 | `/Tenant/Create` | 名称 + 描述 |
| 编辑 | `/Tenant/Edit/{id}` | 名称 + 描述 + 启用状态 |
| 删除 | POST `/Tenant/Delete/{id}` | 有用户关联时禁止删除 |

---

## 7. 用户 API（供外部系统调用）

### 7.1 端点清单

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/users` | GET | 用户列表（支持 tenantId 过滤） |
| `/api/users/{id}` | GET | 用户详情 |
| `/api/users` | POST | 创建用户（带 TenantId） |
| `/api/users/{id}` | PUT | 更新用户 |
| `/api/users/{id}` | DELETE | 软删除用户 |
| `/api/users/{id}/status` | PATCH | 启用/禁用 |
| `/api/users/{id}/unlock` | POST | 解锁账户 |
| `/api/users/{id}/reset-password` | POST | 重置密码 |
| `/api/users/{id}/restore` | POST | 恢复已删除用户 |

### 7.2 认证方式

- JWT Bearer（scope 识别业务系统）
- 当前开发阶段：PermissionEndpointFilter 的 `IsDevelopment()` bypass

---

## 8. 实施状态

| 优先级 | 事项 | 状态 |
|--------|------|------|
| P0 | Controller 重构 | ✅ 完成 |
| P0 | AccountController 拆分（保留 API + 新增 MVC UsersController） | ✅ 完成 |
| P0 | 新增 HomeController | ✅ 完成 |
| P1 | 删除冗余角色和 RoleController | ✅ 完成 |
| P1 | AuthorizationController 服务化（已完成之前回合） | ✅ 完成 |
| P1 | SeedData 清理 | ❌ 待处理 |
| P2 | MVC View 实现（Application/Scope/User/Tenant/Home） | ✅ 完成 |
| P2 | TenantService + TenantController | ✅ 完成 |
| P3 | 审计日志 | ❌ 待处理 |

---

## 9. 端口配置

| 环境 | HTTP | HTTPS | 说明 |
|------|------|-------|------|
| 开发 | 5112 | 7201 | launchSettings.json |
| 生产 | 8080 | — | K3s 容器，Ingress TLS 终止 |
| Docker | 8080 | 8081 | 容器端口 |

---

## 10. 数据库

### 10.1 表结构

| 表 | 说明 |
|----|------|
| Users | 用户池（含 TenantId） |
| Tenants | 租户表 |
| OpenIddictApplications | OAuth 客户端 |
| OpenIddictScopes | 系统级作用域 |
| OpenIddictAuthorizations | 授权记录 |
| OpenIddictTokens | 令牌记录 |
| AspNetUserRoles | 用户角色（待清理） |
| AspNetRoles | 角色（待清理） |

### 10.2 待清理

- `AspNetRoles` 表中的 SuperAdmin/Admin/User/TestUser 角色
- `AspNetUserRoles` 中的用户-角色关联
- 相关的 Identity 角色种子数据
