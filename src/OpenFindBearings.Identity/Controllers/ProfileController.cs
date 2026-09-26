using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Services.Interfaces;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Controllers;

/// <summary>
/// 个人资料控制器 - 修改密码等用户自助操作（MVC 视图）
/// </summary>
    [Authorize]
    public class ProfileController : Controller
{
    private readonly IUserService _userService;
    private readonly SignInManager<OidcUser> _signInManager;
    private readonly ILogger<ProfileController> _logger;

    public ProfileController(
        IUserService userService,
        SignInManager<OidcUser> signInManager,
        ILogger<ProfileController> logger)
    {
        _userService = userService;
        _signInManager = signInManager;
        _logger = logger;
    }

    /// <summary>
    /// 修改密码页面
    /// 改动说明（v2.19.0）：mustChange=1 时为"初始密码强制改密"模式，页面显示不可跳过的警示条
    /// </summary>
    [HttpGet("~/profile/change-password")]
    public IActionResult ChangePassword(string returnUrl = "/", string? realm = null, int mustChange = 0)
    {
        ViewBag.ReturnUrl = returnUrl;
        ViewBag.Realm = realm;
        ViewBag.MustChange = mustChange == 1;
        return View();
    }

    /// <summary>
    /// 处理修改密码提交
    /// </summary>
    [HttpPost("~/profile/change-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request, string returnUrl = "/", string? realm = null)
    {
        if (!ModelState.IsValid)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
        {
            ViewBag.Error = "请先登录";
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        _logger.LogInformation("ProfileController: 修改密码, UserId={UserId}", userId);

        var isValid = await _userService.CheckPasswordAsync(userId, request.CurrentPassword);
        if (!isValid)
        {
            ViewBag.Error = "当前密码错误";
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        var result = await _userService.ResetPasswordAsync(userId, request.NewPassword);
        if (!result.IsSuccess)
        {
            ViewBag.Error = "密码修改失败，请重试";
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        _logger.LogInformation("修改密码成功: UserId={UserId}", userId);

        await _signInManager.SignOutAsync();

        // 改动说明（v2.19.0）：强制改密模式下改完必须重新登录，回跳登录页时保留原 returnUrl
        // （多为 OIDC authorize 绝对地址，过不了下面的本地检查会被丢弃），
        // 保证"登录→强制改密→重新登录→回到原目标"链路不断
        var redirectUrl = returnUrl;
        if (!Url.IsLocalUrl(redirectUrl) && !IsTrustedRedirect(redirectUrl))
            redirectUrl = "/Account/Login?password_changed=1"
                + (string.IsNullOrEmpty(returnUrl) || returnUrl == "/" ? "" : $"&returnUrl={Uri.EscapeDataString(returnUrl)}");
        return Redirect(redirectUrl);
    }

    private static bool IsTrustedRedirect(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        return uri.Host == "localhost" || uri.Host == "127.0.0.1";
    }
}
