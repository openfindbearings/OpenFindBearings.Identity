using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.User;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 账户控制器 - 处理用户注册、登录、资料管理
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            IUserService userService,
            ILogger<AccountController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        #region ========== 公开接口（无需认证）==========

        /// <summary>
        /// 用户注册
        /// </summary>
        [HttpPost("signup")]
        [AllowAnonymous]
        public async Task<ActionResult<ApiResponse<UserResponse>>> SignUp([FromBody] SignUpRequest request)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState
                    .Where(x => x.Value?.Errors.Any() == true)
                    .ToDictionary(
                        x => x.Key,
                        x => x.Value!.Errors.Select(e => e.ErrorMessage).ToArray()
                    );
                return ApiResponseHelper.BadRequest<UserResponse>(this, "Invalid request data", errors);
            }

            if (!request.AgreeTerms)
            {
                return ApiResponseHelper.BadRequest<UserResponse>(this, "You must agree to the terms");
            }

            var dto = new CreateUserDto
            {
                Password = request.Password,
                UserName = request.Account
            };

            UserDto? user;
            if (PhoneNumberHelper.IsValid(dto.UserName))
            {
                dto.PhoneNumber = dto.UserName;
                user = await _userService.GetByPhoneNumberAsync(dto.UserName);
            }
            else if (EmailHelper.IsValid(dto.UserName))
            {
                dto.Email = dto.UserName;
                user = await _userService.GetByEmailAsync(dto.UserName);
            }
            else
            {
                user = await _userService.GetByUsernameAsync(dto.UserName);
            }

            if (user != null)
            {
                _logger.LogWarning("用户注册失败: 账号已存在 {Account}", request.Account);
                return ApiResponseHelper.Conflict<UserResponse>(this, "User already exists");
            }

            var result = await _userService.CreateAsync(dto);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("用户注册失败: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResponseHelper.BadRequest<UserResponse>(
                    this,
                    "Registration failed",
                    result.GetErrorDictionary());
            }

            var response = new UserResponse
            {
                Id = result.Data!.Id,
                UserName = result.Data.UserName,
                Email = result.Data.Email,
                PhoneNumber = result.Data.PhoneNumber
            };

            _logger.LogInformation("用户注册成功: UserId={UserId}, Account={Account}", result.Data.Id, request.Account);

            return ApiResponseHelper.Created(
                this,
                nameof(AdminGetUserById),
                new { id = result.Data.Id },
                response,
                "Registration successful"
            );
        }

        #endregion

        #region ========== 当前用户自己的业务（需要认证）==========

        /// <summary>
        /// 获取当前用户信息（自身）
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<UserResponse>>> GetMyProfile()
        {
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return ApiResponseHelper.Unauthorized<UserResponse>(this, "User not authenticated");
            }

            var user = await _userService.GetByIdAsync(userId.Value);
            if (user == null)
            {
                return ApiResponseHelper.NotFound<UserResponse>(this, "User not found");
            }

            var response = user.ToResponse();
            return ApiResponseHelper.Success(this, response);
        }

        /// <summary>
        /// 更新当前用户资料
        /// </summary>
        [HttpPut("me/profile")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<object>>> UpdateMyProfile([FromBody] UpdateProfileRequest request)
        {
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return ApiResponseHelper.Unauthorized<object>(this, "User not authenticated");
            }

            var dto = request.ToDto();
            var result = await _userService.UpdateAsync(userId.Value, dto);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("更新用户资料失败: UserId={UserId}, Errors={Errors}",
                    userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Update failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("更新用户资料成功: UserId={UserId}", userId);
            return ApiResponseHelper.Success<object>(this, null!, "Profile updated successfully");
        }

        /// <summary>
        /// 修改当前用户密码
        /// </summary>
        [HttpPost("me/change-password")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<object>>> ChangeMyPassword([FromBody] ChangePasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return ApiResponseHelper.BadRequest<object>(this, "Invalid request data");
            }

            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return ApiResponseHelper.Unauthorized<object>(this, "User not authenticated");
            }

            var isValid = await _userService.CheckPasswordAsync(userId.Value, request.CurrentPassword);
            if (!isValid)
            {
                return ApiResponseHelper.BadRequest<object>(this, "Current password is incorrect");
            }

            var result = await _userService.ResetPasswordAsync(userId.Value, request.NewPassword);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Password change failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("修改密码成功: UserId={UserId}", userId);
            return ApiResponseHelper.Success<object>(this, null!, "Password changed successfully");
        }

        /// <summary>
        /// 删除当前用户账户（软删除）
        /// </summary>
        [HttpDelete("me/account")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<object>>> DeleteMyAccount()
        {
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return ApiResponseHelper.Unauthorized<object>(this, "User not authenticated");
            }

            var result = await _userService.DeleteAsync(userId.Value);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("删除账户失败: UserId={UserId}, Errors={Errors}",
                    userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Account deletion failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("删除账户成功: UserId={UserId}", userId);
            return ApiResponseHelper.Success<object>(this, null!, "Account deleted successfully");
        }

        #endregion

        #region ========== 管理员 CRUD 操作（需要 Admin/SuperAdmin 角色）==========

        /// <summary>
        /// 分页获取用户列表（管理员）
        /// </summary>
        [HttpGet("admin/users")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<PaginatedResult<UserResponse>>>> AdminGetUsers([FromQuery] UserQueryRequest request)
        {
            if (request.Page < 1) request.Page = 1;
            if (request.PageSize < 1) request.PageSize = 20;
            if (request.PageSize > 100) request.PageSize = 100;

            var result = await _userService.GetPagedAsync(
                request.Page,
                request.PageSize,
                request.Search,
                request.Status,
                request.Role,
                request.DateFrom,
                request.DateTo,
                request.LastLoginFrom,
                request.LastLoginTo);

            var response = new PaginatedResult<UserResponse>(
                result.Items.Select(u=>u.ToResponse()).ToList(),
                result.TotalCount,
                result.PageIndex,
                result.PageSize);

            return ApiResponseHelper.Success(this, response);
        }

        /// <summary>
        /// 根据ID获取用户（管理员）
        /// </summary>
        [HttpGet("admin/users/{id}")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<UserResponse>>> AdminGetUserById(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);

            if (user == null)
            {
                return ApiResponseHelper.NotFound<UserResponse>(this, "User not found");
            }

            var response = user.ToResponse();
            return ApiResponseHelper.Success(this, response);
        }

        /// <summary>
        /// 创建用户（管理员）
        /// </summary>
        [HttpPost("admin/users")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<UserResponse>>> AdminCreateUser([FromBody] AdminCreateUserRequest request)
        {
            if (!ModelState.IsValid)
            {
                return ApiResponseHelper.BadRequest<UserResponse>(this, "Invalid request data");
            }

            var dto = new CreateUserDto
            {
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Password = request.Password,
                Name = request.Name,
                GivenName = request.GivenName,
                FamilyName = request.FamilyName,
                Nickname = request.Nickname
            };

            var result = await _userService.CreateAsync(dto);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<UserResponse>(
                    this,
                    "Create user failed",
                    result.GetErrorDictionary());
            }

            // 分配角色
            if (request.Roles != null && request.Roles.Any())
            {
                foreach (var role in request.Roles)
                {
                    await _userService.AddToRoleAsync(result.Data!.Id, role);
                }
            }

            var response = result.Data!.ToResponse();
            return ApiResponseHelper.Created(
                this,
                nameof(AdminGetUserById),
                new { id = result.Data!.Id },
                response,
                "User created successfully");
        }

        /// <summary>
        /// 更新用户（管理员）
        /// </summary>
        [HttpPut("admin/users/{id}")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminUpdateUser(Guid id, [FromBody] AdminUpdateUserRequest request)
        {
            var dto = new UpdateUserDto
            {
                Name = request.Name,
                GivenName = request.GivenName,
                FamilyName = request.FamilyName,
                Nickname = request.Nickname,
                PictureUrl = request.PictureUrl,
                WebsiteUrl = request.WebsiteUrl,
                Gender = request.Gender,
                Birthdate = request.Birthdate,
                Locale = request.Locale,
                ZoneInfo = request.ZoneInfo
            };

            if (request.Address != null)
            {
                dto.Address = new Models.ValueObjects.Address
                {
                    Country = request.Address.Country,
                    Region = request.Address.Region,
                    Locality = request.Address.Locality,
                    StreetAddress = request.Address.StreetAddress,
                    PostalCode = request.Address.PostalCode
                };
            }

            var result = await _userService.UpdateAsync(id, dto);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Update failed",
                    result.GetErrorDictionary());
            }

            // 更新角色
            if (request.Roles != null)
            {
                var currentRoles = await _userService.GetRolesAsync(id);
                var rolesToRemove = currentRoles.Except(request.Roles).ToList();
                var rolesToAdd = request.Roles.Except(currentRoles).ToList();

                foreach (var role in rolesToRemove)
                {
                    await _userService.RemoveFromRoleAsync(id, role);
                }
                foreach (var role in rolesToAdd)
                {
                    await _userService.AddToRoleAsync(id, role);
                }
            }

            _logger.LogInformation("管理员更新用户成功: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, "User updated successfully");
        }

        /// <summary>
        /// 删除用户（管理员 - 软删除）
        /// </summary>
        [HttpDelete("admin/users/{id}")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminDeleteUser(Guid id)
        {
            var result = await _userService.DeleteAsync(id);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Delete failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("管理员删除用户: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, "User deleted successfully");
        }

        /// <summary>
        /// 启用/禁用用户（管理员）
        /// </summary>
        [HttpPatch("admin/users/{id}/status")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminToggleUserStatus(Guid id, [FromBody] ToggleUserStatusRequest request)
        {
            ServiceResult result;
            if (request.Enable)
            {
                result = await _userService.EnableAsync(id);
            }
            else
            {
                result = await _userService.DisableAsync(id);
            }

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Status change failed",
                    result.GetErrorDictionary());
            }

            var action = request.Enable ? "enabled" : "disabled";
            _logger.LogInformation("管理员{Action}用户: UserId={UserId}, Operator={Operator}", action, id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, $"User {action} successfully");
        }

        /// <summary>
        /// 解锁用户（管理员）
        /// </summary>
        [HttpPost("admin/users/{id}/unlock")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminUnlockUser(Guid id)
        {
            var result = await _userService.UnlockAsync(id);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Unlock failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("管理员解锁用户: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, "User unlocked successfully");
        }

        /// <summary>
        /// 重置用户密码（管理员）
        /// </summary>
        [HttpPost("admin/users/{id}/reset-password")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<string>>> AdminResetPassword(Guid id, [FromBody] AdminResetPasswordRequest request)
        {
            var result = await _userService.ResetPasswordAsync(id, request.NewPassword);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<string>(
                    this,
                    "Reset password failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("管理员重置用户密码: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success(this, result.Data!, "Password reset successfully");
        }

        #endregion

        #region ========== 辅助方法 ==========

        private Guid? GetCurrentUserId()
        {
            var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr)) return null;
            return Guid.Parse(userIdStr);
        }

        private string? GetCurrentUserName()
        {
            return User.FindFirstValue(ClaimTypes.Name) ?? User.FindFirstValue(ClaimTypes.Email);
        }

        #endregion
    }
}
