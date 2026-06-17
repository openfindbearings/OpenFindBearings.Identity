using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Scope;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// Scope 服务接口 - 管理 OAuth2/OIDC 作用域
    /// </summary>
    public interface IScopeService
    {
        /// <summary>
        /// 分页获取 Scope 列表
        /// </summary>
        Task<PaginatedResult<ScopeDto>> GetPagedAsync(int page, int size, string? search = null, Guid? tenantId = null, CancellationToken ct = default);

        /// <summary>
        /// 根据名称获取 Scope
        /// </summary>
        Task<ScopeDto?> GetByNameAsync(string name, CancellationToken ct = default);

        /// <summary>
        /// 获取所有 Scope
        /// </summary>
        Task<IReadOnlyList<ScopeDto>> GetAllAsync(Guid? tenantId = null, CancellationToken ct = default);

        /// <summary>
        /// 检查 Scope 是否属于指定租户
        /// </summary>
        Task<bool> IsScopeInTenantAsync(string scopeName, Guid? tenantId, CancellationToken ct = default);

        /// <summary>
        /// 创建新 Scope
        /// </summary>
        Task<ServiceResult<ScopeDto>> CreateAsync(CreateScopeDto request, Guid? tenantId = null, CancellationToken ct = default);

        /// <summary>
        /// 更新 Scope
        /// </summary>
        Task<ServiceResult> UpdateAsync(string name, UpdateScopeDto request, CancellationToken ct = default);

        /// <summary>
        /// 删除 Scope
        /// </summary>
        Task<ServiceResult> DeleteAsync(string name, CancellationToken ct = default);
    }
}
