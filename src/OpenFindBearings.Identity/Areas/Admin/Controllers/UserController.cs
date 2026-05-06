using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Areas.Admin.Models.ViewModels;
using OpenFindBearings.Identity.Models.DTOs.Requests;
using OpenFindBearings.Identity.Models.Enums;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class UserController : Controller
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;

        public UserController(IUserService userService, IRoleService roleService)
        {
            _userService = userService;
            _roleService = roleService;
        }

        public async Task<IActionResult> Index(int page = 1, int pageSize = 10, string? search = null, UserStatusFilter? status = null)
        {
            var result = await _userService.GetPagedAsync(page, pageSize, search, status);

            var viewModel = new UserListViewModel
            {
                Users = result,
                SearchKeyword = search,
                StatusFilter = status
            };

            return View(viewModel);
        }

        public async Task<IActionResult> Details(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userService.GetRolesAsync(id);
            user.Roles = roles;

            return View(user);
        }

        public async Task<IActionResult> Create()
        {
            var roles = await _roleService.GetAllAsync();
            var viewModel = new CreateUserViewModel
            {
                AvailableRoles = roles.Select(r => new RoleSelection { Name = r.Name }).ToList()
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                var roles = await _roleService.GetAllAsync();
                model.AvailableRoles = roles.Select(r => new RoleSelection { Name = r.Name }).ToList();
                return View(model);
            }

            var request = new CreateUserRequest
            {
                UserName = model.UserName,
                Email = model.Email,
                Password = model.Password,
                PhoneNumber = model.PhoneNumber,
                Name = model.Name,
                GivenName = model.GivenName,
                FamilyName = model.FamilyName,
                Nickname = model.Nickname
            };

            var result = await _userService.CreateAsync(request);

            if (!result.IsSuccess)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }
                var roles = await _roleService.GetAllAsync();
                model.AvailableRoles = roles.Select(r => new RoleSelection { Name = r.Name }).ToList();
                return View(model);
            }

            if (model.SelectedRoles.Any())
            {
                foreach (var role in model.SelectedRoles)
                {
                    await _userService.AddToRoleAsync(result.Data!.Id, role);
                }
            }

            TempData["Success"] = "用户创建成功";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var allRoles = await _roleService.GetAllAsync();
            var userRoles = await _userService.GetRolesAsync(id);

            var viewModel = new EditUserViewModel
            {
                Id = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                Name = user.Name,
                GivenName = user.GivenName,
                FamilyName = user.FamilyName,
                Nickname = user.Nickname,
                PictureUrl = user.PictureUrl,
                WebsiteUrl = user.WebsiteUrl,
                IsEnabled = user.IsEnabled,
                SelectedRoles = userRoles.ToList(),
                AvailableRoles = allRoles.Select(r => new RoleSelection
                {
                    Name = r.Name,
                    Selected = userRoles.Contains(r.Name)
                }).ToList()
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Guid id, EditUserViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var request = new UpdateUserRequest
            {
                Name = model.Name,
                GivenName = model.GivenName,
                FamilyName = model.FamilyName,
                Nickname = model.Nickname,
                PictureUrl = model.PictureUrl,
                WebsiteUrl = model.WebsiteUrl
            };

            var result = await _userService.UpdateAsync(id, request);

            if (!result.IsSuccess)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }
                return View(model);
            }

            // 更新角色
            var currentRoles = await _userService.GetRolesAsync(id);
            var rolesToAdd = model.SelectedRoles.Except(currentRoles).ToList();
            var rolesToRemove = currentRoles.Except(model.SelectedRoles).ToList();

            foreach (var role in rolesToAdd)
            {
                await _userService.AddToRoleAsync(id, role);
            }

            foreach (var role in rolesToRemove)
            {
                await _userService.RemoveFromRoleAsync(id, role);
            }

            TempData["Success"] = "用户更新成功";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(Guid id)
        {
            var result = await _userService.DeleteAsync(id);

            if (!result.IsSuccess)
            {
                TempData["Error"] = result.Errors.FirstOrDefault();
            }
            else
            {
                TempData["Success"] = "用户删除成功";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public async Task<IActionResult> ToggleEnabled(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            if (user.IsEnabled)
            {
                await _userService.DisableAsync(id);
            }
            else
            {
                await _userService.EnableAsync(id);
            }

            return Ok(new { success = true });
        }

        [HttpPost]
        public async Task<IActionResult> Unlock(Guid id)
        {
            var result = await _userService.UnlockAsync(id);

            if (!result.IsSuccess)
            {
                return BadRequest(new { error = result.Errors.FirstOrDefault() });
            }

            return Ok(new { success = true });
        }
    }
}
