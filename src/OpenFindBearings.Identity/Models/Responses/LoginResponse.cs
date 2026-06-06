namespace OpenFindBearings.Identity.Models.Responses
{
    /// <summary>
    /// 登录响应
    /// </summary>
    public class LoginResponse
    {
        /// <summary>
        /// 访问令牌
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// 令牌类型（通常是 Bearer）
        /// </summary>
        public string TokenType { get; set; } = "Bearer";

        /// <summary>
        /// 过期时间（秒）
        /// </summary>
        public int ExpiresIn { get; set; }

        /// <summary>
        /// 刷新令牌
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// 用户信息
        /// </summary>
        public UserResponse? User { get; set; }
    }
}
