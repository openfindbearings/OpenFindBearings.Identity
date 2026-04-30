using OpenFindBearings.Identity.Models.DTOs;

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
        Task<PaginatedResult<ScopeDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default);

        /// <summary>
        /// 根据名称获取 Scope
        /// </summary>
        Task<ScopeDto?> GetByNameAsync(string name, CancellationToken ct = default);

        /// <summary>
        /// 获取所有 Scope
        /// </summary>
        Task<IReadOnlyList<ScopeDto>> GetAllAsync(CancellationToken ct = default);

        /// <summary>
        /// 创建新 Scope
        /// </summary>
        Task<ServiceResult<ScopeDto>> CreateAsync(CreateScopeRequest request, CancellationToken ct = default);

        /// <summary>
        /// 更新 Scope
        /// </summary>
        Task<ServiceResult> UpdateAsync(string name, UpdateScopeRequest request, CancellationToken ct = default);

        /// <summary>
        /// 删除 Scope
        /// </summary>
        Task<ServiceResult> DeleteAsync(string name, CancellationToken ct = default);
    }
}
