# OpenFindBearings.Identity

OAuth 2.0 / OpenID Connect 认证中心，为所有业务系统提供统一的身份认证和授权服务。

## 技术栈

- .NET 10.0 / ASP.NET Core
- OpenIddict 7.x（OAuth 2.0 / OIDC 服务端）
- SQLite（认证数据库）
- ASP.NET Core Identity（用户管理）

## 核心功能

- **多租户支持**：通过 realm 友好名称识别租户（如 `openfindbearings`）
- **多种认证方式**：用户名+密码、手机号+密码、短信验证码
- **OAuth 2.0 授权**：Authorization Code、Client Credentials、Password、SMS Grant
- **设备绑定**：refresh_token 绑定 device_id，防止跨设备共享
- **自管理 Web UI**：用户/租户/客户端/Scope 管理、个人中心、登录页

## OIDC 客户端

| 客户端 | 授权方式 | 用途 |
|--------|----------|------|
| admin_client | Authorization Code | Admin 管理后台 |
| sync-client | Client Credentials | Sync ETL 服务 |
| maui-client | Password + SMS | 移动端 Taro App |
| web-client | Authorization Code + PKCE | Web 前端 |

## 构建与运行

```bash
cd OpenFindBearings.Identity
dotnet restore
dotnet run --project src/OpenFindBearings.Identity
```

启动后自动迁移数据库并写入种子数据（管理员账号 `Admin@123456`）。

## 部署

```bash
# K3s 部署
kubectl apply -f deploy/k3s/
```

- 域名：`auth.abcsxl.com`
- 数据库：SQLite（可丢库重建，无生产数据）
