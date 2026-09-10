using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Models.DTOs.Scope;
using OpenFindBearings.Identity.Models.DTOs.Tenant;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Controllers
{
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class ScopeController : Controller
    {
        private readonly IScopeService _scopeService;
        private readonly UserManager<OidcUser> _userManager;
        private readonly ITenantService _tenantService;

        public ScopeController(
            IScopeService scopeService,
            UserManager<OidcUser> userManager,
            ITenantService tenantService)
        {
            _scopeService = scopeService;
            _userManager = userManager;
            _tenantService = tenantService;
        }

        private async Task<List<TenantDto>> GetTenantsAsync()
        {
            var tenants = await _tenantService.GetPagedAsync(1, 1000);
            return tenants.Items.ToList();
        }

        private async Task<Guid?> GetCurrentUserTenantIdAsync()
        {
            var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
                return null;
            var user = await _userManager.FindByIdAsync(userIdStr);
            if (user == null) return null;
            return user.TenantId == TenantConstants.SystemTenantId ? null : user.TenantId;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 20, string? search = null)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            var result = await _scopeService.GetPagedAsync(page, pageSize, search, tenantId);
            ViewBag.Search = search;
            return View(result);
        }

        public async Task<IActionResult> Create()
        {
            ViewBag.Tenants = await GetTenantsAsync();
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateScopeDto request)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Tenants = await GetTenantsAsync();
                return View(request);
            }

            // 改动说明：受众输入文本拆成列表交给 service（此前新建 UI 未暴露受众，Resources 恒为 null）
            if (request.ResourcesText != null)
                request.Resources = SplitResources(request.ResourcesText);

            var result = await _scopeService.CreateAsync(request, request.TenantId);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "创建失败");
                ViewBag.Tenants = await GetTenantsAsync();
                return View(request);
            }

            TempData["Success"] = "Scope 创建成功";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(string name)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _scopeService.IsScopeInTenantAsync(name, tenantId))
                return Forbid();

            var scope = await _scopeService.GetByNameAsync(name);
            if (scope == null)
                return NotFound();

            // 改动说明：把 name 传给视图供 POST 回带（原表单漏带导致 name=null→Forbid→保存无反应）；
            // 受众以每行一个文本呈现，编辑时可增删。
            ViewBag.Name = name;
            return View(new UpdateScopeDto
            {
                DisplayName = scope.DisplayName,
                Description = scope.Description,
                Resources = scope.Resources,
                ResourcesText = string.Join("\n", scope.Resources ?? [])
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string name, UpdateScopeDto request)
        {
            // 改动说明：失败回显也要带 name，否则重渲染表单再丢 name。
            ViewBag.Name = name;
            if (!ModelState.IsValid)
                return View(request);

            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _scopeService.IsScopeInTenantAsync(name, tenantId))
                return Forbid();

            // 受众：ResourcesText 非 null 表示本次要改受众，拆分成列表交给 service（空则清空）
            if (request.ResourcesText != null)
                request.Resources = SplitResources(request.ResourcesText);

            var result = await _scopeService.UpdateAsync(name, request);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "更新失败");
                return View(request);
            }

            TempData["Success"] = "Scope 更新成功";
            return RedirectToAction(nameof(Index));
        }

        /// <summary>
        /// 把受众输入文本（每行一个 / 逗号分隔）拆成去重非空列表。
        /// </summary>
        private static List<string> SplitResources(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return new List<string>();
            return text.Split(new[] { '\r', '\n', ',' }, StringSplitOptions.RemoveEmptyEntries)
                       .Select(s => s.Trim())
                       .Where(s => s.Length > 0)
                       .Distinct()
                       .ToList();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string name)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _scopeService.IsScopeInTenantAsync(name, tenantId))
                return Forbid();

            var result = await _scopeService.DeleteAsync(name);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "删除失败";
            else
                TempData["Success"] = "Scope 删除成功";

            return RedirectToAction(nameof(Index));
        }
    }
}
