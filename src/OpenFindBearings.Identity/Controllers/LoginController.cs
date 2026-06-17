using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    public class LoginController : Controller
    {
        private readonly UserManager<OidcUser> _userManager;
        private readonly SignInManager<OidcUser> _signInManager;
        private readonly ITenantResolver _tenantResolver;
        private readonly ILogger<LoginController> _logger;
        private readonly ApplicationDbContext _dbContext;

        public LoginController(
            UserManager<OidcUser> userManager,
            SignInManager<OidcUser> signInManager,
            ITenantResolver tenantResolver,
            ILogger<LoginController> logger,
            ApplicationDbContext dbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tenantResolver = tenantResolver;
            _logger = logger;
            _dbContext = dbContext;
        }

        [HttpGet("~/Account/Login")]
        public async Task<IActionResult> Login(string returnUrl = "/")
        {
            if (Request.Query.TryGetValue("password_changed", out _))
                TempData["PasswordChangedSuccess"] = "密码更改成功，请使用新密码重新登录";

            var tenantInfo = await _tenantResolver.ResolveAsync();
            var tenantId = tenantInfo.TenantId ?? TenantConstants.SystemTenantId;

            ViewBag.TenantId = tenantId;
            ViewBag.Realm = tenantInfo.Realm ?? (tenantId == TenantConstants.SystemTenantId ? TenantConstants.SystemRealm : TenantConstants.OpenFindBearingsRealm);
            ViewBag.RealmDisplayName = tenantInfo.TenantDescription ?? (tenantId == TenantConstants.SystemTenantId ? TenantConstants.SystemDisplayName : TenantConstants.OpenFindBearingsDisplayName);
            ViewBag.Success = TempData["PasswordChangedSuccess"] as string;
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        private void SetViewBagForLogin(Guid? tenantId, string realm, string? description, string? error, string returnUrl)
        {
            var tid = tenantId ?? TenantConstants.SystemTenantId;
            ViewBag.Error = error;
            ViewBag.Success = TempData["PasswordChangedSuccess"] as string;
            ViewBag.ReturnUrl = returnUrl;
            ViewBag.TenantId = tid;
            ViewBag.Realm = realm;
            ViewBag.RealmDisplayName = description;
        }

        [HttpPost("~/Account/Login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginSubmit(string username, string password, string returnUrl = "/")
        {
            var tenantInfo = await _tenantResolver.ResolveAsync();
            var tenantId = tenantInfo.TenantId;

            // 防御性回退：当中间件未解析到租户时，直接从 form 的 realm 字段查库
            if (tenantId == null)
            {
                var formRealm = Request.Form["realm"].FirstOrDefault();
                if (!string.IsNullOrEmpty(formRealm))
                {
                    var tenant = await _dbContext.Tenants.AsNoTracking()
                        .FirstOrDefaultAsync(t => t.Name == formRealm);
                    if (tenant != null)
                    {
                        tenantId = tenant.Id;
                        tenantInfo = new TenantInfo
                        {
                            TenantId = tenant.Id,
                            Realm = formRealm,
                            TenantName = tenant.Name,
                            TenantDescription = tenant.Description
                        };
                        _logger.LogInformation("LoginSubmit: 从表单 realm={Realm} 回退解析到租户 {TenantId}", formRealm, tenant.Id);
                    }
                }
            }

            if (tenantId == null)
            {
                SetViewBagForLogin(TenantConstants.SystemTenantId, "", "", "请求无效：缺少租户信息", returnUrl);
                return View("Login");
            }

            var normalizedUsername = username.ToUpperInvariant();
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUsername && u.TenantId == tenantId.Value);
            if (user == null)
            {
                SetViewBagForLogin(tenantId, tenantInfo.Realm ?? "", tenantInfo.TenantDescription ?? "", "用户名或密码错误", returnUrl);
                return View("Login");
            }

            if (!user.IsAvailable())
            {
                SetViewBagForLogin(tenantId, tenantInfo.Realm ?? "", tenantInfo.TenantDescription ?? "", "账户不可用", returnUrl);
                return View("Login");
            }

            var isValidPassword = await _userManager.CheckPasswordAsync(user, password);
            if (!isValidPassword)
            {
                user.RecordFailedLogin();
                await _userManager.UpdateAsync(user);
                SetViewBagForLogin(tenantId, tenantInfo.Realm ?? "", tenantInfo.TenantDescription ?? "", "用户名或密码错误", returnUrl);
                return View("Login");
            }

            user.RecordSuccessfulLogin(HttpContext.Connection.RemoteIpAddress?.ToString());
            await _userManager.UpdateAsync(user);

            await _signInManager.SignInAsync(user, isPersistent: true);

            _logger.LogInformation("LoginSubmit: 登录成功, UserId={UserId}, Username={Username}, TenantId={TenantId}",
                user.Id, user.UserName, tenantId);

            if (!Url.IsLocalUrl(returnUrl))
                returnUrl = "~/";
            return Redirect(returnUrl);
        }

        [HttpPost("~/Account/Logout")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Redirect("~/Account/Login");
        }
    }
}
