using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Models.DTOs.Client;
using OpenFindBearings.Identity.Models.DTOs.Tenant;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Controllers
{
    [Authorize]
    public class ApplicationController : Controller
    {
        private readonly IClientService _clientService;
        private readonly UserManager<OidcUser> _userManager;
        private readonly ITenantService _tenantService;

        public ApplicationController(
            IClientService clientService,
            UserManager<OidcUser> userManager,
            ITenantService tenantService)
        {
            _clientService = clientService;
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
            var result = await _clientService.GetPagedAsync(page, pageSize, search, tenantId);
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
        public async Task<IActionResult> Create(CreateClientDto request)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Tenants = await GetTenantsAsync();
                return View(request);
            }

            var result = await _clientService.CreateAsync(request, request.TenantId);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "创建失败");
                ViewBag.Tenants = await GetTenantsAsync();
                return View(request);
            }

            TempData["Success"] = "客户端创建成功";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(string clientId)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _clientService.IsClientInTenantAsync(clientId, tenantId))
                return Forbid();

            var client = await _clientService.GetByClientIdAsync(clientId);
            if (client == null)
                return NotFound();

            return View(new UpdateClientDto
            {
                DisplayName = client.DisplayName
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string clientId, UpdateClientDto request)
        {
            if (!ModelState.IsValid)
                return View(request);

            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _clientService.IsClientInTenantAsync(clientId, tenantId))
                return Forbid();

            var result = await _clientService.UpdateAsync(clientId, request);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "更新失败");
                return View(request);
            }

            TempData["Success"] = "客户端更新成功";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string clientId)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _clientService.IsClientInTenantAsync(clientId, tenantId))
                return Forbid();

            var result = await _clientService.DeleteAsync(clientId);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "删除失败";
            else
                TempData["Success"] = "客户端删除成功";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegenerateSecret(string clientId)
        {
            var tenantId = await GetCurrentUserTenantIdAsync();
            if (!await _clientService.IsClientInTenantAsync(clientId, tenantId))
                return Forbid();

            var result = await _clientService.RegenerateSecretAsync(clientId);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "重新生成密钥失败";
            else
            {
                TempData["Success"] = "密钥已重新生成";
                TempData["NewSecret"] = result.Data;
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
