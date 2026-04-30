namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 系统配置实体 - 存储键值对配置
    /// </summary>
    public class SystemConfig
    {
        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// 配置键（唯一）
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// 配置值（JSON 格式）
        /// </summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; set; }
    }
}
