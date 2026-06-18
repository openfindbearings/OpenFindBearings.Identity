using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Tenant;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Services
{
    public class TenantService : ITenantService
    {
        private readonly ApplicationDbContext _db;
        private readonly ILogger<TenantService> _logger;

        public TenantService(ApplicationDbContext db, ILogger<TenantService> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<PaginatedResult<TenantDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default)
        {
            var query = _db.Tenants.AsQueryable();

            if (!string.IsNullOrEmpty(search))
                query = query.Where(t => t.Name.Contains(search) || (t.Description != null && t.Description.Contains(search)));

            var total = await query.CountAsync(ct);
            var items = await query
                .OrderByDescending(t => t.CreatedAt)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            var userIdsByTenant = await _db.Users
                .Where(u => u.TenantId != null)
                .GroupBy(u => u.TenantId!.Value)
                .Select(g => new { TenantId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.TenantId, x => x.Count, ct);

            return new PaginatedResult<TenantDto>(
                items.Select(t => new TenantDto
                {
                    Id = t.Id,
                    Name = t.Name,
                    Description = t.Description,
                    IsEnabled = t.IsEnabled,
                    CreatedAt = t.CreatedAt,
                    UpdatedAt = t.UpdatedAt,
                    UserCount = userIdsByTenant.GetValueOrDefault(t.Id, 0)
                }).ToList(),
                total, page, size);
        }

        public async Task<TenantDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var tenant = await _db.Tenants.FindAsync([id], ct);
            if (tenant == null) return null;

            var userCount = await _db.Users.CountAsync(u => u.TenantId == id, ct);

            return new TenantDto
            {
                Id = tenant.Id,
                Name = tenant.Name,
                Description = tenant.Description,
                IsEnabled = tenant.IsEnabled,
                CreatedAt = tenant.CreatedAt,
                UpdatedAt = tenant.UpdatedAt,
                UserCount = userCount
            };
        }

        public async Task<ServiceResult<TenantDto>> CreateAsync(CreateTenantDto request, CancellationToken ct = default)
        {
            var existing = await _db.Tenants.AnyAsync(t => t.Name == request.Name, ct);
            if (existing)
                return ServiceResult<TenantDto>.Failure([new ServiceError { Code = "TenantAlreadyExists", Description = $"租户 '{request.Name}' 已存在" }]);

            var tenant = new Models.Entities.Tenant
            {
                Id = Guid.NewGuid(),
                Name = request.Name,
                Description = request.Description,
                IsEnabled = true,
                CreatedAt = DateTime.UtcNow
            };

            _db.Tenants.Add(tenant);
            await _db.SaveChangesAsync(ct);

            _logger.LogInformation("创建租户成功: TenantId={TenantId}, Name={Name}", tenant.Id, tenant.Name);

            return ServiceResult<TenantDto>.Success(new TenantDto
            {
                Id = tenant.Id,
                Name = tenant.Name,
                Description = tenant.Description,
                IsEnabled = tenant.IsEnabled,
                CreatedAt = tenant.CreatedAt
            });
        }

        public async Task<ServiceResult> UpdateAsync(Guid id, UpdateTenantDto request, CancellationToken ct = default)
        {
            var tenant = await _db.Tenants.FindAsync([id], ct);
            if (tenant == null)
                return ServiceResult.Failure([new ServiceError { Code = "TenantNotFound", Description = $"租户 '{id}' 不存在" }]);

            tenant.Name = request.Name;
            tenant.Description = request.Description;
            tenant.IsEnabled = request.IsEnabled;
            tenant.UpdatedAt = DateTime.UtcNow;

            await _db.SaveChangesAsync(ct);

            _logger.LogInformation("更新租户成功: TenantId={TenantId}, Name={Name}", id, request.Name);
            return ServiceResult.Success();
        }

        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default)
        {
            var tenant = await _db.Tenants.FindAsync([id], ct);
            if (tenant == null)
                return ServiceResult.Failure([new ServiceError { Code = "TenantNotFound", Description = $"租户 '{id}' 不存在" }]);

            var userCount = await _db.Users.CountAsync(u => u.TenantId == id, ct);
            if (userCount > 0)
                return ServiceResult.Failure([new ServiceError { Code = "TenantHasUsers", Description = $"租户 '{tenant.Name}' 下有 {userCount} 个用户，无法删除" }]);

            _db.Tenants.Remove(tenant);
            await _db.SaveChangesAsync(ct);

            _logger.LogInformation("删除租户成功: TenantId={TenantId}, Name={Name}", id, tenant.Name);
            return ServiceResult.Success();
        }
    }
}
