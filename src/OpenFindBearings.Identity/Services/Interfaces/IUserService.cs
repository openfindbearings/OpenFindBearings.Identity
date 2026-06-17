using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.User;
using OpenFindBearings.Identity.Models.Enums;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 用户服务接口 - 管理用户 CRUD 及用户状态
    /// </summary>
    public interface IUserService
    {
        // ========== 查询 ==========

        /// <summary>
        /// 分页获取用户列表
        /// </summary>
        Task<PaginatedResult<UserDto>> GetPagedAsync(int page, int size, string? search = null, UserStatusFilter? status = null, string? role = null, Guid? tenantId = null, DateTimeOffset? dateFrom = null, DateTimeOffset? dateTo = null, DateTimeOffset? lastLoginFrom = null, DateTimeOffset? lastLoginTo = null, CancellationToken ct = default);

        /// <summary>
        /// 根据 ID 获取用户
        /// </summary>
        Task<UserDto?> GetByIdAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 根据用户名获取用户
        /// </summary>
        Task<UserDto?> GetByUsernameAsync(string username, CancellationToken ct = default);

        /// <summary>
        /// 根据用户名和租户获取用户（限定租户范围）
        /// </summary>
        Task<UserDto?> GetByUsernameAsync(string username, Guid tenantId, CancellationToken ct = default);

        /// <summary>
        /// 根据邮箱获取用户
        /// </summary>
        Task<UserDto?> GetByEmailAsync(string email, CancellationToken ct = default);

        /// <summary>
        /// 根据邮箱和租户获取用户（限定租户范围）
        /// </summary>
        Task<UserDto?> GetByEmailAsync(string email, Guid tenantId, CancellationToken ct = default);

        /// <summary>
        /// 根据手机号获取用户
        /// </summary>
        Task<UserDto?> GetByPhoneNumberAsync(string phoneNumber, CancellationToken ct = default);

        /// <summary>
        /// 根据手机号和租户获取用户（限定租户范围）
        /// </summary>
        Task<UserDto?> GetByPhoneNumberAsync(string phoneNumber, Guid tenantId, CancellationToken ct = default);

        /// <summary>
        /// 获取用户总数
        /// </summary>
        Task<int> GetCountAsync(CancellationToken ct = default);

        // ========== 创建/更新/删除 ==========

        /// <summary>
        /// 创建新用户
        /// </summary>
        Task<ServiceResult<UserDto>> CreateAsync(CreateUserDto request, CancellationToken ct = default);

        /// <summary>
        /// 更新用户信息
        /// </summary>
        Task<ServiceResult> UpdateAsync(Guid id, UpdateUserDto request, CancellationToken ct = default);

        /// <summary>
        /// 软删除用户
        /// </summary>
        Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 恢复软删除的用户
        /// </summary>
        Task<ServiceResult> RestoreAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 启用用户
        /// </summary>
        Task<ServiceResult> EnableAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 禁用用户
        /// </summary>
        Task<ServiceResult> DisableAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 解锁用户
        /// </summary>
        Task<ServiceResult> UnlockAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 重置密码（管理员操作）
        /// </summary>
        Task<ServiceResult<string>> ResetPasswordAsync(Guid id, string newPassword, CancellationToken ct = default);

        // ========== 角色管理 ==========

        /// <summary>
        /// 获取用户的角色列表
        /// </summary>
        Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct = default);

        /// <summary>
        /// 添加用户到角色
        /// </summary>
        Task<ServiceResult> AddToRoleAsync(Guid userId, string role, CancellationToken ct = default);

        /// <summary>
        /// 从角色移除用户
        /// </summary>
        Task<ServiceResult> RemoveFromRoleAsync(Guid userId, string role, CancellationToken ct = default);

        /// <summary>
        /// 设置用户的角色列表（替换现有角色）
        /// </summary>
        Task<ServiceResult> SetRolesAsync(Guid userId, string[] roles, CancellationToken ct = default);

        // ========== 声明管理 ==========

        /// <summary>
        /// 获取用户的声明列表
        /// </summary>
        Task<IReadOnlyList<(string Type, string Value)>> GetClaimsAsync(Guid userId, CancellationToken ct = default);

        /// <summary>
        /// 添加用户声明
        /// </summary>
        Task<ServiceResult> AddClaimAsync(Guid userId, string claimType, string claimValue, CancellationToken ct = default);

        /// <summary>
        /// 移除用户声明
        /// </summary>
        Task<ServiceResult> RemoveClaimAsync(Guid userId, string claimType, string claimValue, CancellationToken ct = default);

        /// <summary>
        /// 检查用户是否可以登录
        /// </summary>
        Task<bool> CheckCanLoginAsync(Guid userId, CancellationToken ct = default);

        /// <summary>
        /// 检查用户密码是否正确
        /// </summary>
        Task<bool> CheckPasswordAsync(Guid userId, string password, CancellationToken ct = default);

        /// <summary>
        /// 记录登录成功
        /// </summary>
        Task RecordLoginSuccessAsync(Guid userId, string? ip = null, CancellationToken ct = default);

        /// <summary>
        /// 记录登录失败
        /// </summary>
        Task RecordLoginFailureAsync(Guid userId, CancellationToken ct = default);
    }
}
