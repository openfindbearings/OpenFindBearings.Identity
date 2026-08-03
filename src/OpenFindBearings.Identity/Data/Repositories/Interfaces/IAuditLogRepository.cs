using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    /// <summary>
    /// 审计日志仓储接口 - 独立定义，不继承 IRepository
    /// 审计日志只有添加和查询，不允许修改和删除
    /// </summary>
    public interface IAuditLogRepository
    {
        // ========== 添加 ==========

        /// <summary>
        /// 添加单条日志
        /// </summary>
        Task AddAsync(AuditLog log, CancellationToken cancellationToken = default);

        /// <summary>
        /// 批量添加日志
        /// </summary>
        Task AddRangeAsync(IEnumerable<AuditLog> logs, CancellationToken cancellationToken = default);

        // ========== 查询 ==========

        /// <summary>
        /// 根据 ID 获取日志
        /// </summary>
        Task<AuditLog?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取所有日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetAllAsync(int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取日志总数
        /// </summary>
        Task<int> GetCountAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// 按操作类型统计日志数量
        /// </summary>
        Task<int> GetCountByActionAsync(string action, CancellationToken cancellationToken = default);

        /// <summary>
        /// 按资源类型统计日志数量
        /// </summary>
        Task<int> GetCountByResourceTypeAsync(string resourceType, CancellationToken cancellationToken = default);

        /// <summary>
        /// 按时间范围统计日志数量
        /// </summary>
        Task<int> GetCountByDateRangeAsync(DateTimeOffset start, DateTimeOffset end, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据用户 ID 获取日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetByUserIdAsync(Guid userId, int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据操作类型获取日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetByActionAsync(string action, int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据资源类型获取日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetByResourceTypeAsync(string resourceType, int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据状态获取日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetByStatusAsync(string status, int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取指定时间范围内的日志（分页）
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetByDateRangeAsync(DateTimeOffset start, DateTimeOffset end, int skip = 0, int take = 100, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取今日日志数量
        /// </summary>
        Task<int> GetTodayCountAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取指定用户的最近日志
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetRecentByUserIdAsync(Guid userId, int take = 10, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取最近的失败日志
        /// </summary>
        Task<IReadOnlyList<AuditLog>> GetRecentFailedAsync(int take = 20, CancellationToken cancellationToken = default);

        // ========== 便捷记录方法 ==========

        /// <summary>
        /// 记录登录日志
        /// </summary>
        Task LogLoginAsync(Guid? userId, string? username, bool success, string? ip, string? clientId, string? failureReason = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录登出日志
        /// </summary>
        Task LogLogoutAsync(Guid? userId, string? username, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录用户操作日志
        /// </summary>
        Task LogUserActionAsync(Guid? userId, string? username, string action, string resourceId, string? details = null, bool success = true, string? failureReason = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录客户端操作日志
        /// </summary>
        Task LogClientActionAsync(Guid? userId, string? username, string action, string clientId, string? details = null, bool success = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录角色操作日志
        /// </summary>
        Task LogRoleActionAsync(Guid? userId, string? username, string action, string roleId, string? details = null, bool success = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录 Scope 操作日志
        /// </summary>
        Task LogScopeActionAsync(Guid? userId, string? username, string action, string scopeName, string? details = null, bool success = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// 记录系统操作日志
        /// </summary>
        Task LogSystemActionAsync(string action, string? details = null, bool success = true, string? failureReason = null, CancellationToken cancellationToken = default);

    }
}
