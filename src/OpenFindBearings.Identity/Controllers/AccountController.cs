using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ViewModels;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 账户控制器 - 处理登录、登出
    /// </summary>
    public class AccountController : Controller
    {
        private readonly SignInManager<OidcUser> _signInManager;
        private readonly UserManager<OidcUser> _userManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            SignInManager<OidcUser> signInManager,
            UserManager<OidcUser> userManager,
            ILogger<AccountController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        /// <summary>
        /// 登录页面
        /// </summary>
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            // 如果已经登录，直接重定向
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToLocal(returnUrl);
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// 登录提交
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // 查找用户
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null)
            {
                user = await _userManager.FindByEmailAsync(model.UserName);
            }

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "用户名或密码错误");
                return View(model);
            }

            // 检查用户是否可登录
            if (!user.IsAvailable())
            {
                ModelState.AddModelError(string.Empty, "账户已被禁用或锁定，请稍后再试");
                return View(model);
            }

            // 验证密码
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("用户 {UserName} 登录成功", user.UserName);

                // 更新最后登录信息
                user.RecordSuccessfulLogin(HttpContext.Connection.RemoteIpAddress?.ToString());
                await _userManager.UpdateAsync(user);

                // 重定向
                return RedirectToLocal(returnUrl);
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "账户已被锁定，请稍后再试");
            }
            else if (result.IsNotAllowed)
            {
                ModelState.AddModelError(string.Empty, "登录失败，请确认账户状态");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "用户名或密码错误");

                // 记录登录失败
                user.RecordFailedLogin();
                await _userManager.UpdateAsync(user);
            }

            return View(model);
        }

        /// <summary>
        /// 登出
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userName = User.Identity?.Name;
            await _signInManager.SignOutAsync();
            _logger.LogInformation("用户 {UserName} 登出", userName);
            return RedirectToAction("Login", "Account");
        }

        /// <summary>
        /// 拒绝访问（无权访问）
        /// </summary>
        [HttpGet]
        public IActionResult AccessDenied(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// 重定向到本地地址
        /// </summary>
        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            // 检查用户角色，默认跳转到对应页面
            if (User.Identity?.IsAuthenticated == true)
            {
                var user = _userManager.GetUserAsync(User).Result;
                if (user != null)
                {
                    var roles = _userManager.GetRolesAsync(user).Result;
                    if (roles.Contains("SuperAdmin") || roles.Contains("Admin"))
                    {
                        return RedirectToAction("Index", "Dashboard", new { area = "Admin" });
                    }
                }
            }

            return RedirectToAction("Index", "Home");
        }
    }
}
