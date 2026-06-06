namespace OpenFindBearings.Identity.Models.Enums
{
    /// <summary>
    /// 用户状态筛选枚举
    /// </summary>
    public enum UserStatusFilter
    {
        /// <summary>
        /// 全部
        /// </summary>
        All = 0,

        /// <summary>
        /// 已启用
        /// </summary>
        Enabled = 1,

        /// <summary>
        /// 已禁用
        /// </summary>
        Disabled = 2,

        /// <summary>
        /// 已锁定
        /// </summary>
        Locked = 3
    }
}
