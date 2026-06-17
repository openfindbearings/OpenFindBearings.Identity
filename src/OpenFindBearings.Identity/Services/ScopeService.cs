using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Scope;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenFindBearings.Identity.Services
{
    public class ScopeService : IScopeService
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IAuditLogRepository _auditLogRepo;
        private readonly ApplicationDbContext _dbContext;

        private static readonly HashSet<string> _standardScopes =
        [
            "openid", "profile", "email", "phone", "address", "roles"
        ];

        public ScopeService(
            IOpenIddictScopeManager scopeManager,
            IAuditLogRepository auditLogRepo,
            ApplicationDbContext dbContext)
        {
            _scopeManager = scopeManager;
            _auditLogRepo = auditLogRepo;
            _dbContext = dbContext;
        }

        public async Task<PaginatedResult<ScopeDto>> GetPagedAsync(int page, int size, string? search = null, Guid? tenantId = null, CancellationToken ct = default)
        {
            var scopesSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope<Guid>>();
            var query = scopesSet.AsNoTracking();

            if (tenantId.HasValue)
            {
                query = query.Where(s => EF.Property<Guid?>(s, "TenantId") == tenantId.Value);
            }

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(s => s.Name != null && s.Name.Contains(search));
            }

            var total = await query.CountAsync(ct);
            var items = await query
                .OrderBy(s => s.Name)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            var scopes = items.Select(s => new ScopeDto
            {
                Name = s.Name ?? string.Empty,
                DisplayName = s.DisplayName ?? string.Empty,
                Description = s.Description,
                Resources = []
            }).ToList();

            return new PaginatedResult<ScopeDto>(scopes, total, page, size);
        }

        public async Task<ScopeDto?> GetByNameAsync(string name, CancellationToken ct = default)
        {
            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null) return null;

            var resources = await _scopeManager.GetResourcesAsync(scope, ct);
            var resourcesList = resources.Any() ? resources.Select(r => r.ToString()).ToList() : [];

            return new ScopeDto
            {
                Name = await _scopeManager.GetNameAsync(scope, ct) ?? string.Empty,
                DisplayName = await _scopeManager.GetDisplayNameAsync(scope, ct) ?? string.Empty,
                Description = await _scopeManager.GetDescriptionAsync(scope, ct),
                Resources = resourcesList
            };
        }

        public async Task<IReadOnlyList<ScopeDto>> GetAllAsync(Guid? tenantId = null, CancellationToken ct = default)
        {
            var scopesSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope<Guid>>();
            var query = scopesSet.AsNoTracking();

            if (tenantId.HasValue)
            {
                query = query.Where(s => EF.Property<Guid?>(s, "TenantId") == tenantId.Value);
            }

            var items = await query.OrderBy(s => s.Name).ToListAsync(ct);
            return items.Select(s => new ScopeDto
            {
                Name = s.Name ?? string.Empty,
                DisplayName = s.DisplayName ?? string.Empty,
                Description = s.Description,
                Resources = []
            }).ToList();
        }

        public async Task<ServiceResult<ScopeDto>> CreateAsync(CreateScopeDto request, Guid? tenantId = null, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(request.Name))
            {
                return ServiceResult<ScopeDto>.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ScopeNameRequired",
                        Description = "Scope 名称不能为空"
                    }
                });
            }

            var existing = await _scopeManager.FindByNameAsync(request.Name, ct);
            if (existing != null)
            {
                return ServiceResult<ScopeDto>.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ScopeAlreadyExists",
                        Description = $"Scope '{request.Name}' 已存在"
                    }
                });
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = request.Name,
                DisplayName = request.DisplayName ?? request.Name,
                Description = request.Description
            };

            if (request.Resources != null)
            {
                foreach (var resource in request.Resources)
                {
                    descriptor.Resources.Add(resource);
                }
            }

            await _scopeManager.CreateAsync(descriptor, ct);

            // 设置 TenantId 影子属性
            if (tenantId.HasValue)
            {
                var scopesSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope<Guid>>();
                var scope = await scopesSet.AsTracking().FirstOrDefaultAsync(s => s.Name == request.Name, ct);
                if (scope != null)
                {
                    _dbContext.Entry(scope).Property("TenantId").CurrentValue = tenantId.Value;
                    await _dbContext.SaveChangesAsync(ct);
                }
            }

            await _auditLogRepo.LogScopeActionAsync(null, "System", "CreateScope", request.Name, null, true, ct);

            return ServiceResult<ScopeDto>.Success(new ScopeDto
            {
                Name = request.Name,
                DisplayName = request.DisplayName ?? request.Name,
                Description = request.Description,
                Resources = request.Resources ?? []
            });
        }

        public async Task<ServiceResult> UpdateAsync(string name, UpdateScopeDto request, CancellationToken ct = default)
        {
            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ScopeNotFound",
                        Description = $"Scope '{name}' 不存在"
                    }
                });
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = request.DisplayName ?? name,
                Description = request.Description
            };

            var existingResources = await _scopeManager.GetResourcesAsync(scope, ct);
            foreach (var resource in existingResources)
            {
                descriptor.Resources.Add(resource);
            }

            await _scopeManager.UpdateAsync(scope, descriptor, ct);

            await _auditLogRepo.LogScopeActionAsync(null, "System", "UpdateScope", name, null, true, ct);
            return ServiceResult.Success();
        }

        public async Task<ServiceResult> DeleteAsync(string name, CancellationToken ct = default)
        {
            if (_standardScopes.Contains(name))
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "CannotDeleteStandardScope",
                        Description = $"标准 OIDC Scope '{name}' 不能删除"
                    }
                });
            }

            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ScopeNotFound",
                        Description = $"Scope '{name}' 不存在"
                    }
                });
            }

            await _scopeManager.DeleteAsync(scope, ct);

            await _auditLogRepo.LogScopeActionAsync(null, "System", "DeleteScope", name, null, true, ct);
            return ServiceResult.Success();
        }

        public async Task<bool> IsScopeInTenantAsync(string scopeName, Guid? tenantId, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(scopeName)) return false;
            if (!tenantId.HasValue) return true;

            var scopesSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope<Guid>>();
            return await scopesSet.AnyAsync(s =>
                s.Name == scopeName &&
                EF.Property<Guid?>(s, "TenantId") == tenantId.Value, ct);
        }
    }
}
