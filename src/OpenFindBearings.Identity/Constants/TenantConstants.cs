namespace OpenFindBearings.Identity.Constants
{
    /// <summary>
    /// 租户常量定义
    /// </summary>
    public static class TenantConstants
    {
        /// <summary>系统租户（Identity 自管理）</summary>
        public static readonly Guid SystemTenantId = Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff");
        /// <summary>系统租户 realm 名称</summary>
        public const string SystemRealm = "system";
        /// <summary>系统租户显示名称</summary>
        public const string SystemDisplayName = "认证中心";

        /// <summary>OpenFindBearings 租户（Admin 业务面板）</summary>
        public static readonly Guid OpenFindBearingsTenantId = Guid.Parse("00000000-0000-0000-0000-000000000001");
        /// <summary>OpenFindBearings 租户 realm 名称</summary>
        public const string OpenFindBearingsRealm = "openfindbearings";
        /// <summary>OpenFindBearings 租户显示名称</summary>
        public const string OpenFindBearingsDisplayName = "轴承管理后台";

        /// <summary>系统管理员用户 ID（Identity 自管理超管）</summary>
        public static readonly Guid SystemAdminUserId = Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");
        /// <summary>业务管理员用户 ID（OpenFindBearings 租户超管，API 同步用）</summary>
        public static readonly Guid BusinessAdminUserId = Guid.Parse("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    }
}
