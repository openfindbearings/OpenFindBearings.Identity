using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 角色管理控制器（自管理后台）。改动说明：补回完整 Role CRUD 界面（此前仅有列表/创建/删除）。
    /// 统一走 IRoleService，控制器不直连 RoleManager/DbContext。
    /// </summary>
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class RoleController : Controller
    {
        private readonly IRoleService _roleService;

        public RoleController(IRoleService roleService)
        {
            _roleService = roleService;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 20, string? search = null)
        {
            var result = await _roleService.GetPagedAsync(page, pageSize, search);
            ViewBag.Search = search;
            return View(result);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                ModelState.AddModelError("", "角色名称不能为空");
                return View();
            }

            var result = await _roleService.CreateAsync(name.Trim());
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "创建失败");
                return View();
            }

            TempData["Success"] = "角色创建成功";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            var role = await _roleService.GetByIdAsync(id);
            if (role == null) return NotFound();
            ViewBag.RoleId = id;
            return View(role);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Guid id, string name)
        {
            ViewBag.RoleId = id;
            if (string.IsNullOrWhiteSpace(name))
            {
                ModelState.AddModelError("", "角色名称不能为空");
                return View(new Models.DTOs.Role.RoleDto { Id = id, Name = name ?? string.Empty });
            }

            var result = await _roleService.UpdateAsync(id, name.Trim());
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "更新失败");
                return View(new Models.DTOs.Role.RoleDto { Id = id, Name = name });
            }

            TempData["Success"] = "角色更新成功";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(Guid id)
        {
            var result = await _roleService.DeleteAsync(id);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "删除失败";
            else
                TempData["Success"] = "角色已删除";
            return RedirectToAction(nameof(Index));
        }
    }
}