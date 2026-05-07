namespace OpenFindBearings.Identity.Models.DTOs.Client
{
    /// <summary>
    /// 客户端数据传输对象 - 用于 API 返回
    /// </summary>
    public class ClientDto
    {
        public string ClientId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string? ClientType { get; set; }
        public IReadOnlyList<string> AllowedScopes { get; set; } = Array.Empty<string>();
        public IReadOnlyList<string> RedirectUris { get; set; } = Array.Empty<string>();
    }
}
