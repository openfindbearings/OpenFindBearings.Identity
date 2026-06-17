using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    [Authorize]
    public class UsersController : Controller
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;
        private readonly ITenantService _tenantService;

        public UsersController(
            IUserService userService,
            IRoleService roleService,
            ITenantService tenantService)
        {
            _userService = userService;
            _roleService = roleService;
            _tenantService = tenantService;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 20, string? search = null, Guid? tenantId = null)
        {
            var result = await _userService.GetPagedAsync(page, pageSize, search, tenantId: tenantId);
            ViewBag.Search = search;
            ViewBag.TenantId = tenantId;

            var tenants = await _tenantService.GetPagedAsync(1, 1000);
            var tenantNames = new Dictionary<Guid, string?>();
            foreach (var t in tenants.Items)
                tenantNames[t.Id] = t.Name;
            ViewBag.TenantNames = tenantNames;
            ViewBag.Tenants = tenants.Items;

            return View(result);
        }

        public async Task<IActionResult> Create()
        {
            ViewBag.Roles = await _roleService.GetAllAsync();
            ViewBag.Tenants = (await _tenantService.GetPagedAsync(1, 1000)).Items;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(AdminCreateUserRequest request)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Roles = await _roleService.GetAllAsync();
                ViewBag.Tenants = (await _tenantService.GetPagedAsync(1, 1000)).Items;
                return View(request);
            }

            var dto = new Models.DTOs.User.CreateUserDto
            {
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Password = request.Password,
                Name = request.Name,
                TenantId = request.TenantId
            };

            var result = await _userService.CreateAsync(dto);
            if (!result.IsSuccess)
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault()?.Description ?? "创建失败");
                ViewBag.Roles = await _roleService.GetAllAsync();
                ViewBag.Tenants = (await _tenantService.GetPagedAsync(1, 1000)).Items;
                return View(request);
            }

            if (request.Roles != null && request.Roles.Any())
            {
                foreach (var role in request.Roles)
                {
                    await _userService.AddToRoleAsync(result.Data!.Id, role);
                }
            }

            TempData["Success"] = "用户创建成功";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleStatus(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null)
                return NotFound();

            if (user.IsEnabled)
                await _userService.DisableAsync(id);
            else
                await _userService.EnableAsync(id);

            TempData["Success"] = "用户状态已更新";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(Guid id)
        {
            var result = await _userService.DeleteAsync(id);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "删除失败";
            else
                TempData["Success"] = "用户已删除";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Restore(Guid id)
        {
            var result = await _userService.RestoreAsync(id);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "恢复失败";
            else
                TempData["Success"] = "用户已恢复";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(Guid id, string newPassword)
        {
            if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
            {
                TempData["Error"] = "密码长度至少 6 位";
                return RedirectToAction(nameof(Index));
            }

            var result = await _userService.ResetPasswordAsync(id, newPassword);
            if (!result.IsSuccess)
                TempData["Error"] = result.Errors.FirstOrDefault()?.Description ?? "重置密码失败";
            else
                TempData["Success"] = "密码重置成功";

            return RedirectToAction(nameof(Index));
        }
    }
}
