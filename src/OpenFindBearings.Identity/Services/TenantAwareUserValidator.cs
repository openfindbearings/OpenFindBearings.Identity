using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Services;

/// <summary>
/// 租户感知用户验证器 — 同租户内用户名唯一，不同租户可重名
/// </summary>
public class TenantAwareUserValidator : UserValidator<OidcUser>
{
    private readonly ApplicationDbContext _context;

    public TenantAwareUserValidator(IdentityErrorDescriber? errors, ApplicationDbContext context)
        : base(errors)
    {
        _context = context;
    }

    /// <summary>
    /// 用户名验证 — 改为同租户内查重
    /// </summary>
    public override async Task<IdentityResult> ValidateAsync(UserManager<OidcUser> manager, OidcUser user)
    {
        var result = await base.ValidateAsync(manager, user);
        if (result.Succeeded)
            return result;

        var errors = result.Errors
            .Where(e => e.Code != "DuplicateUserName" && e.Code != "DuplicateEmail")
            .ToList();

        // 对于 DuplicateUserName 错误，再做租户感知校验
        var hasDuplicateUserName = result.Errors.Any(e => e.Code == "DuplicateUserName");
        if (hasDuplicateUserName)
        {
            var normalizedUserName = manager.NormalizeName(user.UserName!);
            var exists = await _context.Users
                .AnyAsync(u => u.NormalizedUserName == normalizedUserName &&
                               u.TenantId == user.TenantId &&
                               u.Id != user.Id);
            if (exists)
            {
                errors.Add(new IdentityErrorDescriber().DuplicateUserName(user.UserName!));
            }
            // 若不同租户有同名用户，不报错 — 已从 errors 中过滤
        }

        var hasDuplicateEmail = result.Errors.Any(e => e.Code == "DuplicateEmail");
        if (hasDuplicateEmail && !string.IsNullOrEmpty(user.Email))
        {
            var normalizedEmail = manager.NormalizeEmail(user.Email);
            var exists = await _context.Users
                .AnyAsync(u => u.NormalizedEmail == normalizedEmail &&
                               u.TenantId == user.TenantId &&
                               u.Id != user.Id);
            if (exists)
            {
                errors.Add(new IdentityErrorDescriber().DuplicateEmail(user.Email));
            }
        }

        return errors.Count > 0 ? IdentityResult.Failed(errors.ToArray()) : IdentityResult.Success;
    }
}
