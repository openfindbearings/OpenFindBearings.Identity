namespace OpenFindBearings.Identity.Models.DTOs.AuditLog
{
    /// <summary>
    /// 审计日志数据传输对象 - 用于 API 返回
    /// </summary>
    public class AuditLogDto
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public string? Username { get; set; }
        public string Action { get; set; } = string.Empty;
        public string? ResourceType { get; set; }
        public string? ResourceId { get; set; }
        public string? Details { get; set; }
        public string? Status { get; set; }
        public string? FailureReason { get; set; }
        public string? ClientId { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }
}
