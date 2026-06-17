using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.DTOs.Tenant;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    [Authorize]
    public class TenantController : Controller
    {
        private readonly ITenantService _tenantService;

        public TenantController(ITenantService tenantService)
        {
            _tenantService = tenantService;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 20, string? search = null)
        {
            var result = await _tenantService.GetPagedAsync(page, pageSize, search);
            ViewBag.Search = search;
            return View(result);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateTenantDto request)
        {
            if (!ModelState.IsValid)
                return View(request);

            var result = await _tenantService.CreateAsync(request);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "创建失败");
                return View(request);
            }

            TempData["Success"] = "租户创建成功";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            var tenant = await _tenantService.GetByIdAsync(id);
            if (tenant == null)
                return NotFound();

            return View(new UpdateTenantDto
            {
                Name = tenant.Name,
                Description = tenant.Description,
                IsEnabled = tenant.IsEnabled
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Guid id, UpdateTenantDto request)
        {
            if (!ModelState.IsValid)
                return View(request);

            var result = await _tenantService.UpdateAsync(id, request);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "更新失败");
                return View(request);
            }

            TempData["Success"] = "租户更新成功";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(Guid id)
        {
            var result = await _tenantService.DeleteAsync(id);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "删除失败";
            else
                TempData["Success"] = "租户删除成功";

            return RedirectToAction(nameof(Index));
        }
    }
}
