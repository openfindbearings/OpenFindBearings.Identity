namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 令牌吊销服务：在敏感操作（改密/重置/禁用/注销）与移动端单设备互踢场景下，
    /// 主动作废该主体的刷新令牌，使其后续刷新失败（access 令牌因短时效自会过期）。
    /// </summary>
    public interface ITokenRevocationService
    {
        /// <summary>吊销某主体在所有客户端下的全部未撤销刷新令牌（改密/禁用/注销用）</summary>
        Task RevokeAllRefreshTokensAsync(string subject, CancellationToken ct = default);

        /// <summary>仅吊销某主体在指定客户端下的未撤销刷新令牌（移动端单设备互踢用，不波及其它客户端会话）</summary>
        Task RevokeRefreshTokensForClientAsync(string subject, string? clientId, CancellationToken ct = default);
    }
}
