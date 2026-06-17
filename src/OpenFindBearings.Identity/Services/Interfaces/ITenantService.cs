using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Tenant;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    public interface ITenantService
    {
        Task<PaginatedResult<TenantDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default);
        Task<TenantDto?> GetByIdAsync(Guid id, CancellationToken ct = default);
        Task<ServiceResult<TenantDto>> CreateAsync(CreateTenantDto request, CancellationToken ct = default);
        Task<ServiceResult> UpdateAsync(Guid id, UpdateTenantDto request, CancellationToken ct = default);
        Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default);
    }
}
