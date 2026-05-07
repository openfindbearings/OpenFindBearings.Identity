using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.AuditLog;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 审计日志服务实现
    /// </summary>
    public class AuditLogService : IAuditLogService
    {
        private readonly IAuditLogRepository _auditLogRepo;

        public AuditLogService(IAuditLogRepository auditLogRepo)
        {
            _auditLogRepo = auditLogRepo;
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<AuditLogDto>> GetPagedAsync(
            int page, int size,
            string? action = null,
            string? resourceType = null,
            DateTimeOffset? start = null,
            DateTimeOffset? end = null,
            CancellationToken ct = default)
        {
            if (page < 1) page = 1;
            if (size < 1) size = 20;
            if (size > 100) size = 100;

            int skip = (page - 1) * size;
            IReadOnlyList<AuditLog> logs;
            int total;

            // 根据不同的筛选条件调用 Repository 的对应方法
            if (!string.IsNullOrEmpty(action))
            {
                logs = await _auditLogRepo.GetByActionAsync(action, skip, size, ct);
                total = logs.Count;
            }
            else if (!string.IsNullOrEmpty(resourceType))
            {
                logs = await _auditLogRepo.GetByResourceTypeAsync(resourceType, skip, size, ct);
                total = logs.Count;
            }
            else if (start.HasValue || end.HasValue)
            {
                var startDate = start ?? DateTimeOffset.MinValue;
                var endDate = end ?? DateTimeOffset.MaxValue;
                logs = await _auditLogRepo.GetByDateRangeAsync(startDate, endDate, skip, size, ct);
                total = logs.Count;
            }
            else
            {
                logs = await _auditLogRepo.GetAllAsync(skip, size, ct);
                total = await _auditLogRepo.GetCountAsync(ct);
            }

            var dtos = logs.Select(l => l.ToDto()).ToList();
            return new PaginatedResult<AuditLogDto>(dtos, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<AuditLogDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var log = await _auditLogRepo.GetByIdAsync(id, ct);
            return log != null ? log.ToDto() : null;
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<AuditLogDto>> GetByUserIdAsync(Guid userId, int take = 50, CancellationToken ct = default)
        {
            var logs = await _auditLogRepo.GetRecentByUserIdAsync(userId, take, ct);
            return logs.Select(l => l.ToDto()).ToList();
        }

        /// <inheritdoc/>
        public async Task<int> GetTodayCountAsync(CancellationToken ct = default)
        {
            return await _auditLogRepo.GetTodayCountAsync(ct);
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<AuditLogDto>> GetRecentAsync(int take = 20, CancellationToken ct = default)
        {
            var logs = await _auditLogRepo.GetAllAsync(0, take, ct);
            return logs.Select(l=>l.ToDto()).ToList();
        }
    }
}
