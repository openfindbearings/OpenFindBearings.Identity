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
    /// </summary>
    [HttpGet("~/profile/change-password")]
    public IActionResult ChangePassword(string returnUrl = "/", string? realm = null)
    {
        ViewBag.ReturnUrl = returnUrl;
        ViewBag.Realm = realm;
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

        var redirectUrl = returnUrl;
        if (!Url.IsLocalUrl(redirectUrl) && !IsTrustedRedirect(redirectUrl))
            redirectUrl = $"/Account/Login?password_changed=1";
        return Redirect(redirectUrl);
    }

    private static bool IsTrustedRedirect(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        return uri.Host == "localhost" || uri.Host == "127.0.0.1";
    }
}
