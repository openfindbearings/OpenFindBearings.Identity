using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 令牌吊销服务实现。
    /// 做法：直接对 OpenIddict 的 Tokens 表按 Subject（+ Application）将未撤销的刷新令牌置为 revoked。
    /// 说明：刷新令牌在 OpenIddict 校验时要求状态有效，置 revoked 后旧设备刷新即被拒（invalid_grant），
    /// 实现"改密/禁用/注销即时失效"与"移动端单设备互踢"。访问令牌为自包含 JWT、不可吊销，
    /// 依赖其短时效（10 分钟）自然过期，属行业常规。
    /// </summary>
    public class TokenRevocationService : ITokenRevocationService
    {
        // OpenIddict 存储令牌类型/状态的固定字面量（其常量类未公开对应成员，故用与库内一致的字符串值）
        private const string RefreshTokenType = "refresh_token";
        private const string RevokedStatus = "revoked";

        private readonly ApplicationDbContext _db;

        public TokenRevocationService(ApplicationDbContext db)
        {
            _db = db;
        }

        /// <inheritdoc/>
        public async Task RevokeAllRefreshTokensAsync(string subject, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(subject)) return;

            var tokens = await _db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>()
                .Where(t => t.Subject == subject
                            && t.Type == RefreshTokenType
                            && t.Status != RevokedStatus)
                .ToListAsync(ct);

            foreach (var token in tokens)
            {
                token.Status = RevokedStatus;
            }

            if (tokens.Count > 0)
            {
                await _db.SaveChangesAsync(ct);
            }
        }

        /// <inheritdoc/>
        public async Task RevokeRefreshTokensForClientAsync(string subject, string? clientId, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(clientId)) return;

            // 仅吊销该主体在指定客户端下的刷新令牌（经 Application 导航按 ClientId 过滤），
            // 避免波及其它客户端（如 Admin 网页）会话
            var tokens = await _db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>()
                .Where(t => t.Subject == subject
                            && t.Type == RefreshTokenType
                            && t.Status != RevokedStatus
                            && t.Application != null && t.Application.ClientId == clientId)
                .ToListAsync(ct);

            foreach (var token in tokens)
            {
                token.Status = RevokedStatus;
            }

            if (tokens.Count > 0)
            {
                await _db.SaveChangesAsync(ct);
            }
        }
    }
}
