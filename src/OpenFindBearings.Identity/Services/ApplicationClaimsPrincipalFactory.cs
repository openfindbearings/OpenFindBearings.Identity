using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Services;

/// <summary>
/// 登录 Cookie Principal 追加 tenant_id 声明的工厂（v2.17.0）。
/// 默认 UserClaimsPrincipalFactory 只产出 name/roles 等标准声明，管理面租户守卫 Policy
/// 无法从 Cookie 读出租户（只能每请求查库）。本工厂在 SignIn 时一次性写入 tenant_id，
/// 使 IdentitySystemAdmin Policy 可离线校验，零额外查询。
/// </summary>
public class ApplicationClaimsPrincipalFactory : UserClaimsPrincipalFactory<OidcUser, IdentityRole<Guid>>
{
    /// <summary>
    /// 构造工厂（Identity 依赖注入标准三参）
    /// </summary>
    public ApplicationClaimsPrincipalFactory(
        UserManager<OidcUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        IOptions<IdentityOptions> options)
        : base(userManager, roleManager, options)
    {
    }

    /// <summary>
    /// 在默认声明基础上追加 tenant_id（用户无租户时不追加，Policy 自然拒绝）
    /// </summary>
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(OidcUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        if (user.TenantId.HasValue && !identity.HasClaim(c => c.Type == "tenant_id"))
        {
            identity.AddClaim(new Claim("tenant_id", user.TenantId.Value.ToString()));
        }

        return identity;
    }
}
