using OpenFindBearings.Identity.Models.Enums;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 用户查询请求
    /// </summary>
    public class UserQueryRequest
    {
        /// <summary>
        /// 页码（从1开始）
        /// </summary>
        public int Page { get; set; } = 1;

        /// <summary>
        /// 每页大小（默认20，最大100）
        /// </summary>
        public int PageSize { get; set; } = 20;

        /// <summary>
        /// 搜索关键词（用户名/邮箱/姓名/手机号）
        /// </summary>
        public string? Search { get; set; }

        /// <summary>
        /// 状态筛选
        /// </summary>
        public UserStatusFilter? Status { get; set; }

        /// <summary>
        /// 角色筛选
        /// </summary>
        public string? Role { get; set; }

        /// <summary>
        /// 租户筛选
        /// </summary>
        public Guid? TenantId { get; set; }

        /// <summary>
        /// 注册开始时间
        /// </summary>
        public DateTimeOffset? DateFrom { get; set; }

        /// <summary>
        /// 注册结束时间
        /// </summary>
        public DateTimeOffset? DateTo { get; set; }

        /// <summary>
        /// 最后登录开始时间
        /// </summary>
        public DateTimeOffset? LastLoginFrom { get; set; }

        /// <summary>
        /// 最后登录结束时间
        /// </summary>
        public DateTimeOffset? LastLoginTo { get; set; }
    }
}
