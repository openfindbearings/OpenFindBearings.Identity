using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Requests;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// Scope 服务实现
    /// </summary>
    public class ScopeService : IScopeService
    {
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IAuditLogRepository _auditLogRepo;

        /// <summary>
        /// 标准 OIDC Scope 列表（不可删除）
        /// </summary>
        private static readonly HashSet<string> _standardScopes = new()
        {
            "openid", "profile", "email", "phone", "address", "roles"
        };

        public ScopeService(
            IOpenIddictScopeManager scopeManager,
            IAuditLogRepository auditLogRepo)
        {
            _scopeManager = scopeManager;
            _auditLogRepo = auditLogRepo;
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<ScopeDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default)
        {
            var scopes = new List<ScopeDto>();
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope, ct) ?? string.Empty;
                var displayName = await _scopeManager.GetDisplayNameAsync(scope, ct) ?? string.Empty;
                var description = await _scopeManager.GetDescriptionAsync(scope, ct);
                var resources = await _scopeManager.GetResourcesAsync(scope, ct);
                var resourcesList = resources.Any() ? resources.Select(r => r.ToString()).ToList() : new List<string>();

                if (!string.IsNullOrEmpty(search) && !name.Contains(search) && !displayName.Contains(search))
                    continue;

                scopes.Add(new ScopeDto
                {
                    Name = name,
                    DisplayName = displayName,
                    Description = description,
                    Resources = resourcesList
                });
            }

            var total = scopes.Count;
            var paged = scopes.Skip((page - 1) * size).Take(size).ToList();

            return new PaginatedResult<ScopeDto>(paged, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<ScopeDto?> GetByNameAsync(string name, CancellationToken ct = default)
        {
            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null) return null;

            var resources = await _scopeManager.GetResourcesAsync(scope, ct);
            var resourcesList = resources.Any() ? resources.Select(r => r.ToString()).ToList() : new List<string>();

            return new ScopeDto
            {
                Name = await _scopeManager.GetNameAsync(scope, ct) ?? string.Empty,
                DisplayName = await _scopeManager.GetDisplayNameAsync(scope, ct) ?? string.Empty,
                Description = await _scopeManager.GetDescriptionAsync(scope, ct),
                Resources = resourcesList
            };
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<ScopeDto>> GetAllAsync(CancellationToken ct = default)
        {
            var scopes = new List<ScopeDto>();
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var resources = await _scopeManager.GetResourcesAsync(scope, ct);
                var resourcesList = resources.Any() ? resources.Select(r => r.ToString()).ToList() : new List<string>();

                scopes.Add(new ScopeDto
                {
                    Name = await _scopeManager.GetNameAsync(scope, ct) ?? string.Empty,
                    DisplayName = await _scopeManager.GetDisplayNameAsync(scope, ct) ?? string.Empty,
                    Description = await _scopeManager.GetDescriptionAsync(scope, ct),
                    Resources = resourcesList
                });
            }
            return scopes.OrderBy(s => s.Name).ToList();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult<ScopeDto>> CreateAsync(CreateScopeRequest request, CancellationToken ct = default)
        {
            var existing = await _scopeManager.FindByNameAsync(request.Name, ct);
            if (existing != null)
            {
                return ServiceResult<ScopeDto>.Failure($"Scope '{request.Name}' 已存在");
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

            await _auditLogRepo.LogScopeActionAsync(null, "System", "CreateScope", request.Name, null, true, ct);

            return ServiceResult<ScopeDto>.Success(new ScopeDto
            {
                Name = request.Name,
                DisplayName = request.DisplayName ?? request.Name,
                Description = request.Description,
                Resources = request.Resources ?? new List<string>()
            });
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> UpdateAsync(string name, UpdateScopeRequest request, CancellationToken ct = default)
        {
            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null)
            {
                return ServiceResult.Failure($"Scope '{name}' 不存在");
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = request.DisplayName ?? name,
                Description = request.Description
            };

            // 复制现有资源
            var existingResources = await _scopeManager.GetResourcesAsync(scope, ct);
            foreach (var resource in existingResources)
            {
                descriptor.Resources.Add(resource);
            }

            await _scopeManager.UpdateAsync(scope, descriptor, ct);

            await _auditLogRepo.LogScopeActionAsync(null, "System", "UpdateScope", name, null, true, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> DeleteAsync(string name, CancellationToken ct = default)
        {
            // 标准 Scope 不能删除
            if (_standardScopes.Contains(name))
            {
                return ServiceResult.Failure($"标准 OIDC Scope '{name}' 不能删除");
            }

            var scope = await _scopeManager.FindByNameAsync(name, ct);
            if (scope == null)
            {
                return ServiceResult.Failure($"Scope '{name}' 不存在");
            }

            await _scopeManager.DeleteAsync(scope, ct);

            await _auditLogRepo.LogScopeActionAsync(null, "System", "DeleteScope", name, null, true, ct);
            return ServiceResult.Success();
        }
    }
}
