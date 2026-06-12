namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 租户实体
    /// 用于多租户隔离，每个用户必须归属一个租户
    /// </summary>
    public class Tenant
    {
        /// <summary>
        /// 租户主键
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// 租户名称（如 "OpenFindBearings"）
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// 是否启用
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// 更新时间
        /// </summary>
        public DateTime? UpdatedAt { get; set; }
    }
}
