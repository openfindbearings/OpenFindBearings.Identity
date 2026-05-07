using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Role;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 角色服务接口 - 管理角色 CRUD 及角色声明
    /// </summary>
    public interface IRoleService
    {
        // ========== 查询 ==========

        /// <summary>
        /// 分页获取角色列表
        /// </summary>
        Task<PaginatedResult<RoleDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default);

        /// <summary>
        /// 获取所有角色
        /// </summary>
        Task<IReadOnlyList<RoleDto>> GetAllAsync(CancellationToken ct = default);

        /// <summary>
        /// 根据 ID 获取角色
        /// </summary>
        Task<RoleDto?> GetByIdAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 根据名称获取角色
        /// </summary>
        Task<RoleDto?> GetByNameAsync(string name, CancellationToken ct = default);

        /// <summary>
        /// 检查角色是否存在
        /// </summary>
        Task<bool> ExistsAsync(string name, CancellationToken ct = default);

        // ========== 创建/更新/删除 ==========

        /// <summary>
        /// 创建新角色
        /// </summary>
        Task<ServiceResult<RoleDto>> CreateAsync(string name, CancellationToken ct = default);

        /// <summary>
        /// 删除角色
        /// </summary>
        Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 获取角色的用户数量
        /// </summary>
        Task<int> GetUserCountAsync(string roleName, CancellationToken ct = default);
    }
}
