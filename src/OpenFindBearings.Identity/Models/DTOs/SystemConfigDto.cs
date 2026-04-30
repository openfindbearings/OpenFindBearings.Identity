namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 系统配置数据传输对象 - 用于 API 返回
    /// </summary>
    public class SystemConfigDto
    {
        public string Key { get; set; } = string.Empty;
        public string? Value { get; set; }
        public string? Description { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }
}
