namespace OpenFindBearings.Identity.Models.DTOs.Client
{
    /// <summary>
    /// 更新客户端请求
    /// </summary>
    public class UpdateClientDto
    {
        /// <summary>
        /// 显示名称
        /// </summary>
        public string DisplayName { get; set; } = string.Empty;

        /// <summary>
        /// 客户端类型
        /// </summary>
        public string? ClientType { get; set; }

        /// <summary>
        /// 同意类型
        /// </summary>
        public string? ConsentType { get; set; }

        /// <summary>
        /// 回调地址（每行一个）。改动说明：补充 Keycloak 式可编辑回调。
        /// </summary>
        public string? RedirectUrisText { get; set; }

        /// <summary>
        /// 登出回调地址（每行一个）。改动说明：补充 Keycloak 式可编辑登出回调。
        /// </summary>
        public string? PostLogoutUrisText { get; set; }

        /// <summary>
        /// 允许的作用域（勾选集合）。改动说明：补充 Keycloak 式作用域分配。
        /// </summary>
        public IReadOnlyList<string>? AllowedScopes { get; set; }
    }
}
