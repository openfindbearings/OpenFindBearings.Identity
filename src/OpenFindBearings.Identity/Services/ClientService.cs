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

            return new ClientDto
            {
                ClientId = app.ClientId ?? string.Empty,
                DisplayName = app.DisplayName ?? string.Empty,
                ClientType = app.ClientType ?? string.Empty
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

        public async Task<ServiceResult> UpdateAsync(string clientId, UpdateClientDto request, CancellationToken ct = default)
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

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = request.DisplayName
            };

            var permissions = await _applicationManager.GetPermissionsAsync(app, ct);
            foreach (var permission in permissions)
            {
                descriptor.Permissions.Add(permission);
            }

            await _applicationManager.UpdateAsync(app, descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "UpdateClient", clientId, null, true, ct);
            return ServiceResult.Success();
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
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = newSecret,
                DisplayName = await _applicationManager.GetDisplayNameAsync(app, ct)
            };

            await _applicationManager.UpdateAsync(app, descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "RegenerateSecret", clientId, null, true, ct);
            return ServiceResult<string>.Success(newSecret);
        }
    }
}
