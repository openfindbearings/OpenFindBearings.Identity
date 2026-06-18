# OpenFindBearings.Identity 认证中心设计文档

**版本：** v1.1.0  
**日期：** 2026-06-12  
**状态：** 设计完成，待实施

---

## 变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0.0 | 2026-05-07 | 初始版本：用户管理、角色管理、OpenIddict 基础配置 |
| v1.0.1 | 2026-06-01 | 新增 restore 端点 |
| v1.1.0 | 2026-06-12 | 新增 Tenant 基础设施、OIDC 授权端点、登录页 |

---

## 1. 总体架构

OpenFindBearings.Identity 是全局认证中心，负责 OIDC 认证和系统级 scope，不管理各业务系统的细粒度 RBAC。

```
Identity 认证中心
├── OIDC 服务端（OpenIddict）
│   ├── /connect/authorize（授权端点）  ← v1.1.0 新增
│   ├── /connect/token（令牌端点）
│   ├── /connect/userinfo（用户信息端点）
│   └── /connect/logout（登出端点）
├── 用户管理（CRUD + 状态管理）
├── 角色管理（系统级角色：SuperAdmin/Admin/User）
├── 租户管理（v1.1.0 新增）
└── 审计日志
```

## 2. 多租户架构（v1.1.0 新增）

### 2.1 设计决策

Identity 作为全局认证中心，需要支持多个业务系统。通过 TenantId 实现租户隔离。

| 概念 | 说明 |
|------|------|
| Tenant | 业务系统标识（如 OpenFindBearings） |
| TenantId | Guid 类型，非空，每个用户必须归属一个租户 |
| 租户与用户 | 一对多关系，一个租户包含多个用户 |
| 租户与角色 | 无关。Identity 角色是系统级，Admin 业务角色是应用级 |

### 2.2 Tenant 实体

```csharp
public class Tenant
{
    public Guid Id { get; set; }           // 主键
    public string Name { get; set; }       // 租户名称
    public string? Description { get; set; } // 描述
    public bool IsEnabled { get; set; }    // 是否启用
    public DateTime CreatedAt { get; set; } // 创建时间
    public DateTime? UpdatedAt { get; set; } // 更新时间
}
```

### 2.3 OidcUser 新增 TenantId

```csharp
// OidcUser 实体新增
public Guid TenantId { get; set; }  // 非空，FK → Tenant
```

### 2.4 种子数据

```csharp
public static class TenantConstants
{
    public const string OpenFindBearings = "00000000-0000-0000-0000-000000000001";
}

// 种子 Tenant
new Tenant
{
    Id = Guid.Parse(TenantConstants.OpenFindBearings),
    Name = "OpenFindBearings",
    Description = "OpenFindBearings 轴承信息管理系统",
    IsEnabled = true,
    CreatedAt = DateTime.UtcNow
}
```

现有种子用户（admin/zhangsan/lisi/wangwu）全部关联到此 TenantId。

### 2.5 JWT Token 中的 tenant_id

`/connect/token` 端点在构造 claims 时加入 `tenant_id`：

```csharp
var tenantId = await GetTenantIdAsync(userId);
claims.Add(new Claim("tenant_id", tenantId.ToString()));
```

## 3. OIDC 授权端点（v1.1.0 新增）

### 3.1 流程

```
1. 客户端（Admin）→ GET /connect/authorize?response_type=code&client_id=admin_client&...
2. Identity 检查用户登录状态
3. 未登录 → 跳转登录页
4. 已登录 → 检查 consent_type
5. consent_type=Implicit → 自动授予 → 回调 redirect_uri?code=xxx
6. consent_type=Explicit → 跳转同意页 → 用户确认 → 回调
```

### 3.2 端点定义

| 端点 | 方法 | 说明 |
|------|------|------|
| `/connect/authorize` | GET | 授权请求入口 |
| `/connect/authorize/accept` | POST | 授予授权码 |
| `/connect/authorize/deny` | POST | 拒绝授权 |

### 3.3 admin_client 配置

```csharp
new OpenIddictApplication
{
    ClientId = "admin_client",
    ClientSecret = "admin-secret-key",
    ConsentType = ConsentTypes.Implicit,  // 跳过同意页
    Permissions =
    {
        OpenIddictConstants.Permissions.Endpoints.Authorization,
        OpenIddictConstants.Permissions.Endpoints.Token,
        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
        OpenIddictConstants.Permissions.ResponseTypes.Code,
        OpenIddictConstants.Permissions.Scopes.Email,
        OpenIddictConstants.Permissions.Scopes.Profile,
        OpenIddictConstants.Permissions.Scopes.Roles,
        OpenIddictConstants.Permissions.Prefixes.Scope + "api"
    },
    RedirectUris = { "https://localhost:7167/callback" },
    PostLogoutRedirectUris = { "https://localhost:7167/" }
};
```

### 3.4 开发环境 ServiceExtensions 配置

```csharp
options.AllowAuthorizationCodeFlow()
       .AllowRefreshTokenFlow();
```

### 3.5 生产环境回调地址维护

OpenIddict 的 redirect_uri 存储在数据库 `OpenIddictApplications` 表中。维护方式：

| 场景 | 操作 |
|------|------|
| 首次部署 | 更新 SeedData 或通过 ApplicationController 端点更新 |
| 域名变更 | 调用 `PUT /api/applications/{id}` 更新 redirect_uris |
| 多环境共存 | 同一 ClientId 可注册多个 redirect_uri |

### 3.6 CORS 配置

```json
{
  "AllowedOrigins": [
    "https://localhost:7167",
    "https://www.simate.cn",
    "https://simate.cn"
  ]
}
```

## 4. 登录页（v1.1.0 新增）

### 4.1 设计要求

- 现代感设计，不强制与 Admin 风格一致
- 简洁表单：用户名 + 密码 + 登录按钮
- 响应式布局
- 错误提示

### 4.2 页面结构

```
Views/Authorization/
├── _Layout.cshtml     ← 登录页专用布局（现代感设计）
├── Login.cshtml       ← 登录表单
```

### 4.3 登录流程

```
1. 用户访问 Admin → 跳转 Identity /connect/authorize
2. Identity 检查未登录 → 跳转 /Authorization/Login
3. 用户提交用户名/密码 → POST /api/Account/Login
4. 验证成功 → 设置认证 Cookie → 回调 /connect/authorize
5. /connect/authorize 授予 code → 回调 Admin /callback
6. Admin 用 code 换 JWT → 存 Cookie → 登录完成
```

## 5. 用户管理端点

### 5.1 管理端点（已有）

| 端点 | 方法 | 权限 | 说明 |
|------|------|------|------|
| `/api/Account/admin/users` | GET | SuperAdmin/Admin | 用户列表（v1.1.0 新增 tenantId 过滤） |
| `/api/Account/admin/users/{id}` | GET | SuperAdmin/Admin | 用户详情 |
| `/api/Account/admin/users` | POST | SuperAdmin/Admin | 创建用户（v1.1.0 自动关联 TenantId） |
| `/api/Account/admin/users/{id}` | PUT | SuperAdmin/Admin | 更新用户 |
| `/api/Account/admin/users/{id}` | DELETE | SuperAdmin/Admin | 软删除用户 |
| `/api/Account/admin/users/{id}/status` | PATCH | SuperAdmin/Admin | 启用/禁用 |
| `/api/Account/admin/users/{id}/unlock` | POST | SuperAdmin/Admin | 解锁账户 |
| `/api/Account/admin/users/{id}/reset-password` | POST | SuperAdmin/Admin | 重置密码 |
| `/api/Account/admin/users/{id}/restore` | POST | SuperAdmin/Admin | 恢复已删除用户 |

### 5.2 TenantId 过滤

`GET /api/Account/admin/users` 新增查询参数：

```
GET /api/Account/admin/users?tenantId=00000000-0000-0000-0000-000000000001&page=1&pageSize=20
```

`UserService.GetPagedAsync` 方法新增 `tenantId` 参数，按租户过滤用户。

### 5.3 创建用户关联 TenantId

`POST /api/Account/admin/users` 请求体新增 `tenantId` 字段。创建用户时自动设置 `OidcUser.TenantId`。

## 6. Tenant 管理端点

| 端点 | 方法 | 权限 | 说明 |
|------|------|------|------|
| `/api/tenants` | GET | SuperAdmin/Admin | 租户列表 |
| `/api/tenants` | POST | SuperAdmin/Admin | 创建租户 |
| `/api/tenants/{id}` | PUT | SuperAdmin/Admin | 更新租户 |
| `/api/tenants/{id}` | DELETE | SuperAdmin/Admin | 删除租户 |

当前 Phase 1 仅使用 SeedData 硬编码的 OpenFindBearings 租户，Tenant CRUD 留待后续多租户需求。

## 7. 数据库变更

### 7.1 新增表

```sql
CREATE TABLE "Tenants" (
    "Id" uuid NOT NULL,
    "Name" text NOT NULL,
    "Description" text,
    "IsEnabled" boolean NOT NULL DEFAULT true,
    "CreatedAt" timestamp with time zone NOT NULL,
    "UpdatedAt" timestamp with time zone,
    CONSTRAINT "PK_Tenants" PRIMARY KEY ("Id")
);
```

### 7.2 修改表

```sql
ALTER TABLE "Users" ADD "TenantId" uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE "Users" ADD CONSTRAINT "FK_Users_Tenants_TenantId"
    FOREIGN KEY ("TenantId") REFERENCES "Tenants" ("Id") ON DELETE RESTRICT;
CREATE INDEX "IX_Users_TenantId" ON "Users" ("TenantId");
```

## 8. 端口配置

| 环境 | HTTP | HTTPS | 说明 |
|------|------|-------|------|
| 开发 | 5112 | 7201 | launchSettings.json |
| 生产 | 8080 | — | K3s 容器，Ingress TLS 终止 |
| Docker | 8080 | 8081 | 容器端口 |

## 9. 与其他项目的边界

| 职责 | Identity | Admin | API |
|------|----------|-------|-----|
| 用户认证 | ✅ OIDC | — | JWT 验证 |
| 用户 CRUD | ✅ | 调用 API | — |
| 系统级角色 | ✅ SuperAdmin/Admin/User | — | — |
| 业务级 RBAC | — | ✅ admin_role_permissions | PermissionFilter |
| 租户管理 | ✅ | — | — |
| 权限校验 | — | 本地 if/else | PermissionFilter |
