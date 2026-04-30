using OpenFindBearings.Identity.Models.DTOs;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// 审计日志视图模型 - 列表页
    /// </summary>
    public class AuditLogListViewModel
    {
        public PaginatedResult<AuditLogDto> Logs { get; set; } = null!;
        public string? ActionFilter { get; set; }
        public string? ResourceTypeFilter { get; set; }
        public DateTimeOffset? StartDate { get; set; }
        public DateTimeOffset? EndDate { get; set; }

        /// <summary>
        /// 可用的操作类型
        /// </summary>
        public List<string> AvailableActions { get; set; } = new();

        /// <summary>
        /// 可用的资源类型
        /// </summary>
        public List<string> AvailableResourceTypes { get; set; } = new();
    }

    /// <summary>
    /// 审计日志视图模型
    /// </summary>
    public class AuditLogViewModel
    {
        [Display(Name = "ID")]
        public Guid Id { get; set; }

        [Display(Name = "用户ID")]
        public Guid? UserId { get; set; }

        [Display(Name = "用户名")]
        public string? Username { get; set; }

        [Display(Name = "操作")]
        public string Action { get; set; } = string.Empty;

        [Display(Name = "资源类型")]
        public string? ResourceType { get; set; }

        [Display(Name = "资源ID")]
        public string? ResourceId { get; set; }

        [Display(Name = "详情")]
        public string? Details { get; set; }

        [Display(Name = "状态")]
        public string? Status { get; set; }

        [Display(Name = "失败原因")]
        public string? FailureReason { get; set; }

        [Display(Name = "客户端ID")]
        public string? ClientId { get; set; }

        [Display(Name = "IP地址")]
        public string? IpAddress { get; set; }

        [Display(Name = "时间")]
        public DateTimeOffset CreatedAt { get; set; }
    }
}
