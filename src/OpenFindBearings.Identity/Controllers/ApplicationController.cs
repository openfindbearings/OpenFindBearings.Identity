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
    [Authorize(Policy = "IdentitySystemAdmin")]
    public class ApplicationController : Controller
    {
        private readonly IClientService _clientService;
        private readonly UserManager<OidcUser> _userManager;
        private readonly ITenantService _tenantService;
        private readonly IScopeService _scopeService;

        public ApplicationController(
            IClientService clientService,
            UserManager<OidcUser> userManager,
            ITenantService tenantService,
            IScopeService scopeService)
        {
            _clientService = clientService;
            _userManager = userManager;
            _tenantService = tenantService;
            // 改动说明：注入 ScopeService，供客户端编辑页分配允许作用域（Keycloak 式）。
            _scopeService = scopeService;
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

            // 改动说明：把 clientId 传给视图，供编辑表单以 asp-route-clientId 回带到 POST
            // （原表单漏带 clientId → POST 时 clientId=null → IsClientInTenant 返回 Forbid，保存无反应）。
            // 同时把完整 ClientDto 放入 ViewBag.Client 供页面只读展示；AllScopes 供作用域勾选；
            // ScopeAudiences（scope→受众 JSON）供"令牌受众预览"由勾选实时推导。
            ViewBag.ClientId = clientId;
            ViewBag.Client = client;
            var scopes = await _scopeService.GetAllAsync();
            ViewBag.AllScopes = scopes.Select(s => s.Name).ToList();
            ViewBag.ScopeAudiences = System.Text.Json.JsonSerializer.Serialize(
                scopes.ToDictionary(s => s.Name, s => (s.Resources ?? Enumerable.Empty<string>()).ToList()));
            return View(new UpdateClientDto
            {
                DisplayName = client.DisplayName,
                ClientType = client.ClientType,
                ConsentType = client.ConsentType,
                RedirectUrisText = string.Join("\n", client.RedirectUris),
                PostLogoutUrisText = string.Join("\n", client.PostLogoutRedirectUris),
                AllowedScopes = client.AllowedScopes
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string clientId, UpdateClientDto request)
        {
            // 改动说明：失败回显时也要带上 clientId，否则重渲染的表单又丢失 clientId、二次保存仍失败。
            ViewBag.ClientId = clientId;
            // 改动说明：回显时补全作用域下拉与只读详情，避免视图空引用；受众预览数据同 GET 分支。
            var reload = await _clientService.GetByClientIdAsync(clientId);
            ViewBag.Client = reload;
            var scopes = await _scopeService.GetAllAsync();
            ViewBag.AllScopes = scopes.Select(s => s.Name).ToList();
            ViewBag.ScopeAudiences = System.Text.Json.JsonSerializer.Serialize(
                scopes.ToDictionary(s => s.Name, s => (s.Resources ?? Enumerable.Empty<string>()).ToList()));
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
