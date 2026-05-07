namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 设置系统配置请求
    /// </summary>
    public class SetSystemConfigRequest
    {
        /// <summary>
        /// 配置值（支持字符串、数字、对象等）
        /// </summary>
        public object Value { get; set; } = null!;

        /// <summary>
        /// 配置描述
        /// </summary>
        public string? Description { get; set; }
    }
}
