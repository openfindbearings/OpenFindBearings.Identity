using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    /// <summary>
    /// 审计日志仓储实现 - 只有添加和查询，不允许修改和删除
    /// </summary>
    public class AuditLogRepository : IAuditLogRepository
    {
        private readonly ApplicationDbContext _context;

        public AuditLogRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // ========== 添加 ==========

        /// <summary>
        /// 添加单条日志
        /// </summary>
        public async Task AddAsync(AuditLog log, CancellationToken cancellationToken = default)
        {
            //log.CreatedAt = DateTimeOffset.UtcNow;
            await _context.AuditLogs.AddAsync(log, cancellationToken);
        }

        /// <summary>
        /// 批量添加日志
        /// </summary>
        public async Task AddRangeAsync(IEnumerable<AuditLog> logs, CancellationToken cancellationToken = default)
        {
            //var list = logs.ToList();
            //foreach (var log in list)
            //{
            //    log.CreatedAt = DateTimeOffset.UtcNow;
            //}
            await _context.AuditLogs.AddRangeAsync(logs, cancellationToken);
        }

        // ========== 查询 ==========

        /// <summary>
        /// 根据 ID 获取日志
        /// </summary>
        public async Task<AuditLog?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs.FirstOrDefaultAsync(l => l.Id == id, cancellationToken);
        }

        /// <summary>
        /// 获取所有日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetAllAsync(int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 获取日志总数
        /// </summary>
        public async Task<int> GetCountAsync(CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 按操作类型统计日志数量
        /// </summary>
        public async Task<int> GetCountByActionAsync(string action, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs.CountAsync(l => l.Action == action, cancellationToken);
        }

        /// <summary>
        /// 按资源类型统计日志数量
        /// </summary>
        public async Task<int> GetCountByResourceTypeAsync(string resourceType, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs.CountAsync(l => l.ResourceType == resourceType, cancellationToken);
        }

        /// <summary>
        /// 按时间范围统计日志数量
        /// </summary>
        public async Task<int> GetCountByDateRangeAsync(DateTimeOffset start, DateTimeOffset end, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs.CountAsync(l => l.CreatedAt >= start && l.CreatedAt <= end, cancellationToken);
        }

        /// <summary>
        /// 根据用户 ID 获取日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetByUserIdAsync(Guid userId, int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.UserId == userId)
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 根据操作类型获取日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetByActionAsync(string action, int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.Action == action)
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 根据资源类型获取日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetByResourceTypeAsync(string resourceType, int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.ResourceType == resourceType)
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 根据状态获取日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetByStatusAsync(string status, int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.Status == status)
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 获取指定时间范围内的日志（分页）
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetByDateRangeAsync(DateTimeOffset start, DateTimeOffset end, int skip = 0, int take = 100, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.CreatedAt >= start && l.CreatedAt <= end)
                .OrderByDescending(l => l.CreatedAt)
                .Skip(skip)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 获取今日日志数量
        /// </summary>
        public async Task<int> GetTodayCountAsync(CancellationToken cancellationToken = default)
        {
            var today = DateTimeOffset.UtcNow.Date;
            var tomorrow = today.AddDays(1);

            return await _context.AuditLogs
                .Where(l => l.CreatedAt >= today && l.CreatedAt < tomorrow)
                .CountAsync(cancellationToken);
        }

        /// <summary>
        /// 获取指定用户的最近日志
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetRecentByUserIdAsync(Guid userId, int take = 10, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.UserId == userId)
                .OrderByDescending(l => l.CreatedAt)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 获取最近的失败日志
        /// </summary>
        public async Task<IReadOnlyList<AuditLog>> GetRecentFailedAsync(int take = 20, CancellationToken cancellationToken = default)
        {
            return await _context.AuditLogs
                .Where(l => l.Status == "Failed")
                .OrderByDescending(l => l.CreatedAt)
                .Take(take)
                .ToListAsync(cancellationToken);
        }

        // ========== 便捷记录方法 ==========

        /// <summary>
        /// 记录登录日志
        /// </summary>
        public async Task LogLoginAsync(Guid? userId, string? username, bool success, string? ip, string? clientId, string? failureReason = null, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateLogin(userId, username, success, ip, clientId, failureReason);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录登出日志
        /// </summary>
        public async Task LogLogoutAsync(Guid? userId, string? username, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateLogout(userId, username);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录用户操作日志
        /// </summary>
        public async Task LogUserActionAsync(Guid? userId, string? username, string action, string resourceId, string? details = null, bool success = true, string? failureReason = null, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateUserAction(userId, username, action, resourceId, details, success, failureReason);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录客户端操作日志
        /// </summary>
        public async Task LogClientActionAsync(Guid? userId, string? username, string action, string clientId, string? details = null, bool success = true, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateClientAction(userId, username, action, clientId, details, success);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录角色操作日志
        /// </summary>
        public async Task LogRoleActionAsync(Guid? userId, string? username, string action, string roleId, string? details = null, bool success = true, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateRoleAction(userId, username, action, roleId, details, success);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录 Scope 操作日志
        /// </summary>
        public async Task LogScopeActionAsync(Guid? userId, string? username, string action, string scopeName, string? details = null, bool success = true, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateScopeAction(userId, username, action, scopeName, details, success);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 记录系统操作日志
        /// </summary>
        public async Task LogSystemActionAsync(string action, string? details = null, bool success = true, string? failureReason = null, CancellationToken cancellationToken = default)
        {
            var log = AuditLog.CreateSystemAction(action, details, success, failureReason);
            await AddAsync(log, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}
