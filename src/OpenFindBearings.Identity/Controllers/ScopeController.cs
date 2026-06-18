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
    [Authorize]
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

            return View(new UpdateScopeDto
            {
                DisplayName = scope.DisplayName,
                Description = scope.Description
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string name, UpdateScopeDto request)
        {
            if (!ModelState.IsValid)
                return View(request);

            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _scopeService.IsScopeInTenantAsync(name, tenantId))
                return Forbid();

            var result = await _scopeService.UpdateAsync(name, request);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "更新失败");
                return View(request);
            }

            TempData["Success"] = "Scope 更新成功";
            return RedirectToAction(nameof(Index));
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
