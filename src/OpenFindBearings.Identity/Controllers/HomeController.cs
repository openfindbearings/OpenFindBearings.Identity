using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 认证中心后台首页（仪表盘统计）。
    /// 改动说明：统计一律经各 service 获取，控制器不再直连 DbContext / OpenIddict 实体
    /// （原直连非泛型 string 键实体查的是空壳表，计数恒为 0，且删掉 options.UseOpenIddict() 后会抛异常）。
    /// </summary>
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IUserService _userService;
        private readonly ITenantService _tenantService;
        private readonly IClientService _clientService;
        private readonly IScopeService _scopeService;

        public HomeController(
            IUserService userService,
            ITenantService tenantService,
            IClientService clientService,
            IScopeService scopeService)
        {
            _userService = userService;
            _tenantService = tenantService;
            _clientService = clientService;
            _scopeService = scopeService;
        }

        public async Task<IActionResult> Index()
        {
            ViewBag.UserCount = await _userService.GetCountAsync();
            ViewBag.TenantCount = await _tenantService.GetCountAsync();
            ViewBag.ClientCount = await _clientService.GetCountAsync();
            ViewBag.ScopeCount = await _scopeService.GetCountAsync();
            return View();
        }
    }
}
