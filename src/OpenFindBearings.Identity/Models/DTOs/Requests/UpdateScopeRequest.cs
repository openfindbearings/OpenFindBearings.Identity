namespace OpenFindBearings.Identity.Models.DTOs.Requests
{
    /// <summary>
    /// 更新 Scope 请求
    /// </summary>
    public class UpdateScopeRequest
    {
        /// <summary>
        /// 显示名称
        /// </summary>
        public string? DisplayName { get; set; }

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; set; }
    }
}
