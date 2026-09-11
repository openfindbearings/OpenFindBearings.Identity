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

        /// <summary>
        /// 已知受众（资源标识符）目录：代码常量 + 全部既有 scope 已用资源的并集（+当前编辑项），
        /// 供受众编辑器 datalist 建议；新增后台服务时在 ApiResourceConstants 加常量即可进入目录。
        /// </summary>
        private async Task<List<string>> GetKnownAudiencesAsync(IEnumerable<string>? extra = null)
        {
            var used = (await _scopeService.GetAllAsync())
                .SelectMany(s => s.Resources ?? (IReadOnlyList<string>)Array.Empty<string>());
            return new[] { ApiResourceConstants.BaseApi, ApiResourceConstants.SyncApi }
                .Concat(used)
                .Concat(extra ?? Enumerable.Empty<string>())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .OrderBy(s => s)
                .ToList();
        }

        public async Task<IActionResult> Create()
        {
            ViewBag.Tenants = await GetTenantsAsync();
            // 改动说明：受众编辑器数据源（Keycloak Included Audience 范式）
            ViewBag.AudienceKnown = await GetKnownAudiencesAsync();
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

            // 改动说明：受众编辑器以 hidden Resources 列表 + resourcesSubmitted 标记提交——
            // 有标记则按提交值采纳（空列表=明确清空受众）；无标记的旧式调用回退 ResourcesText 拆分
            if (Request.Form.ContainsKey("resourcesSubmitted"))
            {
                request.Resources = request.Resources ?? new List<string>();
            }
            else if (request.ResourcesText != null)
            {
                request.Resources = SplitResources(request.ResourcesText);
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

            // 改动说明：把 name 传给视图供 POST 回带（原表单漏带导致 name=null→Forbid→保存无反应）；
            // 受众改由行式编辑器呈现（当前值 + 已知资源建议）
            ViewBag.Name = name;
            ViewBag.AudienceCurrent = scope.Resources;
            ViewBag.AudienceKnown = await GetKnownAudiencesAsync(scope.Resources);
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

            // 受众：编辑器提交（有 resourcesSubmitted 标记）时按 hidden 列表整体替换（空=清空）；
            // 无标记的旧式调用保留 null=不修改、ResourcesText 拆分的原语义
            if (Request.Form.ContainsKey("resourcesSubmitted"))
            {
                request.Resources = request.Resources ?? new List<string>();
            }
            else if (request.ResourcesText != null)
            {
                request.Resources = SplitResources(request.ResourcesText);
            }

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
