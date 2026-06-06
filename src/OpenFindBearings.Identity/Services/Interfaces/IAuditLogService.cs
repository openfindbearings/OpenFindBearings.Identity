using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.AuditLog;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 审计日志服务接口 - 查询和统计审计日志
    /// </summary>
    public interface IAuditLogService
    {
        /// <summary>
        /// 分页获取审计日志
        /// </summary>
        Task<PaginatedResult<AuditLogDto>> GetPagedAsync(int page, int size, string? action = null, string? resourceType = null, DateTimeOffset? start = null, DateTimeOffset? end = null, CancellationToken ct = default);

        /// <summary>
        /// 根据 ID 获取日志详情
        /// </summary>
        Task<AuditLogDto?> GetByIdAsync(Guid id, CancellationToken ct = default);

        /// <summary>
        /// 获取指定用户的日志
        /// </summary>
        Task<IReadOnlyList<AuditLogDto>> GetByUserIdAsync(Guid userId, int take = 50, CancellationToken ct = default);

        /// <summary>
        /// 获取今日日志数量
        /// </summary>
        Task<int> GetTodayCountAsync(CancellationToken ct = default);

        /// <summary>
        /// 获取最近的操作日志
        /// </summary>
        Task<IReadOnlyList<AuditLogDto>> GetRecentAsync(int take = 20, CancellationToken ct = default);
    }
}
