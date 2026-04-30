namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 角色数据传输对象 - 用于 API 返回
    /// </summary>
    public class RoleDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public int UserCount { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }
}
