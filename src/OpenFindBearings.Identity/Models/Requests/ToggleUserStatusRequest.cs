namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 切换用户状态请求
    /// </summary>
    public class ToggleUserStatusRequest
    {
        /// <summary>true=启用, false=禁用</summary>
        public bool Enable { get; set; }
    }
}
