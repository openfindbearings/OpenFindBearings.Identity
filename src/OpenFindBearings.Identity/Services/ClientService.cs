using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Client;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Services
{
    public class ClientService : IClientService
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IAuditLogRepository _auditLogRepo;
        private readonly ApplicationDbContext _dbContext;

        public ClientService(
            IOpenIddictApplicationManager applicationManager,
            IAuditLogRepository auditLogRepo,
            ApplicationDbContext dbContext)
        {
            _applicationManager = applicationManager;
            _auditLogRepo = auditLogRepo;
            _dbContext = dbContext;
        }

        public async Task<PaginatedResult<ClientDto>> GetPagedAsync(int page, int size, string? search = null, Guid? tenantId = null, CancellationToken ct = default)
        {
            var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();

            var query = appsSet.AsNoTracking();

            if (tenantId.HasValue)
            {
                query = query.Where(a => EF.Property<Guid?>(a, "TenantId") == tenantId.Value);
            }

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(a => a.ClientId != null &&
                    (a.ClientId.Contains(search) || (a.DisplayName != null && a.DisplayName.Contains(search))));
            }

            var total = await query.CountAsync(ct);
            var items = await query
                .OrderBy(a => a.ClientId)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            var clients = items.Select(a => new ClientDto
            {
                ClientId = a.ClientId ?? string.Empty,
                DisplayName = a.DisplayName ?? string.Empty,
                ClientType = a.ClientType ?? string.Empty
            }).ToList();

            return new PaginatedResult<ClientDto>(clients, total, page, size);
        }

        public async Task<int> GetCountAsync(Guid? tenantId = null, CancellationToken ct = default)
        {
            // 改动说明：仪表盘统计客户端数量走 service，控制器不再直连 DbContext/实体。
            var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            var query = appsSet.AsNoTracking();
            if (tenantId.HasValue)
                query = query.Where(a => EF.Property<Guid?>(a, "TenantId") == tenantId.Value);
            return await query.CountAsync(ct);
        }

        public async Task<bool> IsClientInTenantAsync(string clientId, Guid? tenantId, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(clientId)) return false;
            if (!tenantId.HasValue) return true;

            var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            return await appsSet.AnyAsync(a =>
                a.ClientId == clientId &&
                EF.Property<Guid?>(a, "TenantId") == tenantId.Value, ct);
        }

        public async Task<ClientDto?> GetByClientIdAsync(string clientId, CancellationToken ct = default)
        {
            var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            var app = await appsSet.AsNoTracking()
                .FirstOrDefaultAsync(a => a.ClientId == clientId, ct);
            if (app == null) return null;

            // 改动说明：补全详情字段（只读展示用）。RedirectUris/PostLogout/Permissions 用 manager getter
            // 读取（实体上这些是序列化列，manager 负责解析）；AllowedScopes 从 scp: 权限推导（OpenIddict
            // 应用本身不存作用域列，客户端允许的 scope 就是它权限里 scp: 前缀的列表）。
            var permissions = await _applicationManager.GetPermissionsAsync(app, ct);
            var allowedScopes = permissions
                .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.Ordinal))
                .Select(p => p[OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
                .ToList();

            return new ClientDto
            {
                ClientId = app.ClientId ?? string.Empty,
                DisplayName = app.DisplayName ?? string.Empty,
                ClientType = app.ClientType,
                ConsentType = app.ConsentType,
                AllowedScopes = allowedScopes,
                RedirectUris = (await _applicationManager.GetRedirectUrisAsync(app, ct)).ToList(),
                PostLogoutRedirectUris = (await _applicationManager.GetPostLogoutRedirectUrisAsync(app, ct)).ToList(),
                Permissions = permissions.ToList()
            };
        }

        public async Task<ServiceResult<ClientDto>> CreateAsync(CreateClientDto request, Guid? tenantId = null, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(request.ClientId))
            {
                return ServiceResult<ClientDto>.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ClientIdRequired",
                        Description = "客户端 ID 不能为空"
                    }
                });
            }

            var existing = await _applicationManager.FindByClientIdAsync(request.ClientId, ct);
            if (existing != null)
            {
                return ServiceResult<ClientDto>.Failure(new[]
                 {
                    new ServiceError
                    {
                        Code = "ClientAlreadyExists",
                        Description = $"客户端 '{request.ClientId}' 已存在"
                    }
                });
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                DisplayName = request.DisplayName,
                ConsentType = ConsentTypes.Explicit
            };

            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);

            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                descriptor.RedirectUris.Add(new Uri(request.RedirectUri));
            }

            if (request.Scopes != null)
            {
                foreach (var scope in request.Scopes)
                {
                    descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
                }
            }

            await _applicationManager.CreateAsync(descriptor, ct);

            // 设置 TenantId 影子属性
            if (tenantId.HasValue)
            {
                var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
                var app = await appsSet.AsTracking().FirstOrDefaultAsync(a => a.ClientId == request.ClientId, ct);
                if (app != null)
                {
                    _dbContext.Entry(app).Property("TenantId").CurrentValue = tenantId.Value;
                    await _dbContext.SaveChangesAsync(ct);
                }
            }

            await _auditLogRepo.LogClientActionAsync(null, "System", "CreateClient", request.ClientId, null, true, ct);

            return ServiceResult<ClientDto>.Success(new ClientDto
            {
                ClientId = request.ClientId,
                DisplayName = request.DisplayName
            });
        }

        /// <summary>
        /// 从现有 application 克隆出完整 descriptor（读-改-写全量）。
        /// 改动说明：OpenIddict 的 UpdateAsync 以传入 descriptor 整体覆盖应用记录；
        /// 原 Update/RegenerateSecret 只填了部分字段即提交，导致 RedirectUris/PostLogout/ClientType/
        /// ConsentType/Permissions 等被抹掉（保存一次即丢配置）。故更新前先克隆全部既有字段，
        /// 调用方再改目标字段，杜绝误删。
        /// </summary>
        private async Task<OpenIddictApplicationDescriptor> CloneDescriptorAsync(object app, CancellationToken ct)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = await _applicationManager.GetClientIdAsync(app, ct),
                ClientType = await _applicationManager.GetClientTypeAsync(app, ct),
                ConsentType = await _applicationManager.GetConsentTypeAsync(app, ct),
                DisplayName = await _applicationManager.GetDisplayNameAsync(app, ct)
            };

            foreach (var uri in await _applicationManager.GetRedirectUrisAsync(app, ct))
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }
            foreach (var uri in await _applicationManager.GetPostLogoutRedirectUrisAsync(app, ct))
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
            }
            foreach (var permission in await _applicationManager.GetPermissionsAsync(app, ct))
            {
                descriptor.Permissions.Add(permission);
            }

            return descriptor;
        }

        public async Task<ServiceResult> UpdateAsync(string clientId, UpdateClientDto request, CancellationToken ct = default)
        {
            var appsSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            var entity = await appsSet.FirstOrDefaultAsync(a => a.ClientId == clientId, ct);
            if (entity == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            // 改动说明：元数据编辑（当前仅 DisplayName）改为直接经 DbContext 改单字段，不再走
            // manager.UpdateAsync(descriptor)。原因：CloneDescriptorAsync 无法回传机密客户端的
            // client_secret（库里只有哈希、给不出明文），manager 会因"confidential 客户端 secret 不能为空"
            // 抛 ValidationException 导致保存失败；而直接改单字段天然不会抹掉 RedirectUris/Permissions/Secret，
            // 比"读-改-写全量 descriptor"更安全。密钥变更走 RegenerateSecretAsync（那里显式提供新 secret）。
            if (request.DisplayName != null)
            {
                entity.DisplayName = request.DisplayName;
            }

            // 改动说明：补齐 Keycloak 式可编辑字段——访问类型/同意类型/回调/登出回调/允许作用域。
            // 一律直接改实体对应列（沿用"直改实体绕开 secret 校验"的做法）：
            //  - RedirectUris/PostLogoutRedirectUris/Permissions 是 JSON 序列化列，用 JsonSerializer 写；
            //  - 作用域仅重建 scp:* 权限（按勾选全量替换），ept:/* 等其它权限原样保留，避免破坏端点授权。
            if (!string.IsNullOrEmpty(request.ClientType))
            {
                entity.ClientType = request.ClientType;
            }
            if (!string.IsNullOrEmpty(request.ConsentType))
            {
                entity.ConsentType = request.ConsentType;
            }
            if (request.RedirectUrisText != null)
            {
                entity.RedirectUris = SerializeTextList(request.RedirectUrisText);
            }
            if (request.PostLogoutUrisText != null)
            {
                entity.PostLogoutRedirectUris = SerializeTextList(request.PostLogoutUrisText);
            }
            if (request.AllowedScopes != null)
            {
                var current = DeserializeTextList(entity.Permissions);
                var kept = current.Where(p => !p.StartsWith("scp:", StringComparison.Ordinal)).ToList();
                var scp = request.AllowedScopes
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Select(s => "scp:" + s.Trim())
                    .Distinct();
                entity.Permissions = System.Text.Json.JsonSerializer.Serialize(kept.Concat(scp).ToList());
            }

            await _dbContext.SaveChangesAsync(ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "UpdateClient", clientId, null, true, ct);
            return ServiceResult.Success();
        }

        /// <summary>
        /// 把"每行一个/逗号分隔"的文本拆成去重列表并序列化为 JSON 数组字符串（OpenIddict 列格式）。
        /// </summary>
        private static string SerializeTextList(string? text)
        {
            var items = (text ?? string.Empty)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct()
                .ToList();
            return System.Text.Json.JsonSerializer.Serialize(items);
        }

        /// <summary>
        /// 反序列化 OpenIddict JSON 数组列；无法解析时返回空列表。
        /// </summary>
        private static List<string> DeserializeTextList(string? json)
        {
            if (string.IsNullOrWhiteSpace(json)) return new List<string>();
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }

        public async Task<ServiceResult> DeleteAsync(string clientId, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            await _applicationManager.DeleteAsync(app, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "DeleteClient", clientId, null, true, ct);
            return ServiceResult.Success();
        }

        public async Task<ServiceResult<string>> RegenerateSecretAsync(string clientId, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null)
            {
                return ServiceResult<string>.Failure(new[]
                 {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            var newSecret = Guid.NewGuid().ToString("N");
            // 改动说明：读-改-写——先克隆全部既有配置再仅替换 ClientSecret，
            // 原实现只带 ClientId/Secret/DisplayName 提交，会把 RedirectUris/Permissions 一并抹掉。
            var descriptor = await CloneDescriptorAsync(app, ct);
            descriptor.ClientSecret = newSecret;

            await _applicationManager.UpdateAsync(app, descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "RegenerateSecret", clientId, null, true, ct);
            return ServiceResult<string>.Success(newSecret);
        }
    }
}
