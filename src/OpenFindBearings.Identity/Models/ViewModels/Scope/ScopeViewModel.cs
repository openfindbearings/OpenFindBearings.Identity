namespace OpenFindBearings.Identity.Models.ViewModels.Scope
{
    /// <summary>
    /// 权限范围视图模型 - 用于前端界面展示
    /// </summary>
    public class ScopeViewModel
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string? DisplayName { get; set; }
        public List<string>? Resources { get; set; }
    }
}