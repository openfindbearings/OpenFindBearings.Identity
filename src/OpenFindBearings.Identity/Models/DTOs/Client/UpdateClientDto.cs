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
    }
}
