namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// Scope 数据传输对象 - 用于 API 返回
    /// </summary>
    public class ScopeDto
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string? Description { get; set; }
        public IReadOnlyList<string> Resources { get; set; } = Array.Empty<string>();
    }
}
