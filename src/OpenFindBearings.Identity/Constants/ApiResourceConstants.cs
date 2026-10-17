namespace OpenFindBearings.Identity.Constants
{
    /// <summary>
    /// 开源基座内置的 API 资源受众常量。
    /// 改动说明（v2.18.0 通用扩展机制）：移除 SyncApi——扩展资源改由 IIdentityExtension 贡献，
    /// 开源 Identity 不再出现 扩展资源/scope。
    /// </summary>
    public static class ApiResourceConstants
    {
        public const string BaseApi = "openfindbearings-api";
    }
}
