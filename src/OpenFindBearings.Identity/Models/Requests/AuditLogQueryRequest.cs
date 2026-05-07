namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 审计日志查询请求
    /// </summary>
    public class AuditLogQueryRequest
    {
        /// <summary>页码（从1开始）</summary>
        public int Page { get; set; } = 1;

        /// <summary>每页大小（默认20，最大100）</summary>
        public int PageSize { get; set; } = 20;

        /// <summary>操作类型筛选（Login、Logout、CreateUser 等）</summary>
        public string? Action { get; set; }

        /// <summary>资源类型筛选（User、Role、Client、Scope 等）</summary>
        public string? ResourceType { get; set; }

        /// <summary>开始时间</summary>
        public DateTimeOffset? StartDate { get; set; }

        /// <summary>结束时间</summary>
        public DateTimeOffset? EndDate { get; set; }
    }
}
