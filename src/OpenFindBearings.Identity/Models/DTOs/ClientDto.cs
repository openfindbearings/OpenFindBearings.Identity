using System.Text.Json;

namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 客户端数据传输对象 - 用于层间数据传输
    /// </summary>
    public class ClientDto
    {
        public string ClientId { get; set; } = string.Empty;
        public string? ClientSecret { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string? ClientType { get; set; }
        public string? ConsentType { get; set; }
        public HashSet<string> Permissions { get; set; } = [];
        public HashSet<Uri> RedirectUris { get; set; } = [];
        public HashSet<Uri> PostLogoutRedirectUris { get; set; } = [];
        public Dictionary<string, JsonElement> Properties { get; set; } = [];
        public HashSet<string> Requirements { get; set; } = [];
    }
}