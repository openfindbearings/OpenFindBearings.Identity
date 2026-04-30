using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
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
        public async Task<PaginatedResult<AuditLogDto>> GetPagedAsync(int page, int size, string? action = null, string? resourceType = null, DateTimeOffset? start = null, DateTimeOffset? end = null, CancellationToken ct = default)
        {
            var query = await _auditLogRepo.GetAllAsync(0, int.MaxValue, ct);
            var list = query.ToList();

            if (!string.IsNullOrEmpty(action))
            {
                list = list.Where(x => x.Action == action).ToList();
            }

            if (!string.IsNullOrEmpty(resourceType))
            {
                list = list.Where(x => x.ResourceType == resourceType).ToList();
            }

            if (start.HasValue)
            {
                list = list.Where(x => x.CreatedAt >= start.Value).ToList();
            }

            if (end.HasValue)
            {
                list = list.Where(x => x.CreatedAt <= end.Value).ToList();
            }

            var total = list.Count;
            var paged = list.OrderByDescending(x => x.CreatedAt).Skip((page - 1) * size).Take(size).ToList();
            var dtos = paged.Select(MapToDto).ToList();

            return new PaginatedResult<AuditLogDto>(dtos, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<AuditLogDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var log = await _auditLogRepo.GetByIdAsync(id, ct);
            return log != null ? MapToDto(log) : null;
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<AuditLogDto>> GetByUserIdAsync(Guid userId, int take = 50, CancellationToken ct = default)
        {
            var logs = await _auditLogRepo.GetRecentByUserIdAsync(userId, take, ct);
            return logs.Select(MapToDto).ToList();
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
            return logs.Select(MapToDto).ToList();
        }

        /// <summary>
        /// 实体转DTO
        /// </summary>
        private static AuditLogDto MapToDto(AuditLog log)
        {
            return new AuditLogDto
            {
                Id = log.Id,
                UserId = log.UserId,
                Username = log.Username,
                Action = log.Action,
                ResourceType = log.ResourceType,
                ResourceId = log.ResourceId,
                Details = log.Details,
                Status = log.Status,
                FailureReason = log.FailureReason,
                ClientId = log.ClientId,
                IpAddress = log.IpAddress,
                UserAgent = log.UserAgent,
                CreatedAt = log.CreatedAt
            };
        }
    }
}
