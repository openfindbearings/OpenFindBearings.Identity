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
        /// <summary>
        /// 同意类型（ConsentType）。改动说明：编辑页只读展示，便于审计与 Keycloak 式详情。
        /// </summary>
        public string? ConsentType { get; set; }
        public IReadOnlyList<string> AllowedScopes { get; set; } = Array.Empty<string>();
        public IReadOnlyList<string> RedirectUris { get; set; } = Array.Empty<string>();
        /// <summary>
        /// 登出后重定向 URI 列表。改动说明：编辑页只读展示。
        /// </summary>
        public IReadOnlyList<string> PostLogoutRedirectUris { get; set; } = Array.Empty<string>();
        /// <summary>
        /// 权限列表（端点权限）。改动说明：编辑页只读展示，涉及机密凭证不开放编辑。
        /// </summary>
        public IReadOnlyList<string> Permissions { get; set; } = Array.Empty<string>();
    }
}
