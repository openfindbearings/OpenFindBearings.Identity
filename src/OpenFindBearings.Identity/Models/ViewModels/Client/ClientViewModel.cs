namespace OpenFindBearings.Identity.Models.ViewModels.Client
{
    /// <summary>
    /// 客户端视图模型 - 用于前端界面展示
    /// </summary>
    public class ClientViewModel
    {
        public string ClientId { get; set; } = string.Empty;
        public string? ClientSecret { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string? ClientType { get; set; }
        public string? ConsentType { get; set; }
        public List<string> Permissions { get; set; } = [];
        public List<string> RedirectUris { get; set; } = [];
        public List<string> PostLogoutRedirectUris { get; set; } = [];
        public DateTimeOffset? CreatedAt { get; set; }
    }
}