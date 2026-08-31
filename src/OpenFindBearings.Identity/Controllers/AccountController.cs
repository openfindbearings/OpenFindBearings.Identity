using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.User;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 账户控制器 - 处理用户注册、登录、资料管理
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public class AccountController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            IUserService userService,
            ApplicationDbContext context,
            ILogger<AccountController> logger)
        {
            _userService = userService;
            _context = context;
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

            // 解析 realm 为租户 ID
            Guid? tenantId = null;
            if (!string.IsNullOrEmpty(request.Realm))
            {
                var tenant = await _context.Tenants.AsNoTracking()
                    .FirstOrDefaultAsync(t => t.Name == request.Realm);
                if (tenant != null) tenantId = tenant.Id;
            }

            if (tenantId == null)
            {
                return ApiResponseHelper.BadRequest<UserResponse>(this, "Invalid realm");
            }

            var dto = new CreateUserDto
            {
                Password = request.Password,
                UserName = request.Account,
                TenantId = tenantId
            };

            UserDto? user;
            if (PhoneNumberHelper.IsValid(dto.UserName))
            {
                dto.PhoneNumber = dto.UserName;
                user = await _userService.GetByPhoneNumberAsync(dto.UserName, tenantId.Value);
            }
            else if (EmailHelper.IsValid(dto.UserName))
            {
                dto.Email = dto.UserName;
                user = await _userService.GetByEmailAsync(dto.UserName, tenantId.Value);
            }
            else
            {
                user = await _userService.GetByUsernameAsync(dto.UserName, tenantId.Value);
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

            // 员工邀请码暂存为用户声明，后续 JIT 创建业务用户时读取
            if (!string.IsNullOrEmpty(request.InviteCode))
            {
                var claimResult = await _userService.AddClaimAsync(result.Data.Id, "invite_code", request.InviteCode);
                if (claimResult.IsSuccess)
                {
                    _logger.LogInformation("邀请码已存入用户声明: UserId={UserId}, InviteCode={InviteCode}",
                        result.Data.Id, request.InviteCode);
                }
            }

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

            // 未传 tenantId 时使用当前管理员 JWT 中的 tenant_id claim
            var effectiveTenantId = request.TenantId;
            if (!effectiveTenantId.HasValue)
            {
                var tidClaim = User.FindFirst("tenant_id")?.Value;
                if (!string.IsNullOrEmpty(tidClaim) && Guid.TryParse(tidClaim, out var tid))
                    effectiveTenantId = tid;
            }

            var result = await _userService.GetPagedAsync(
                request.Page,
                request.PageSize,
                request.Search,
                request.Status,
                request.Role,
                effectiveTenantId,
                request.DateFrom,
                request.DateTo,
                request.LastLoginFrom,
                request.LastLoginTo,
                request.IncludeDeleted);

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
            var user = await GetTenantUserAsync(id);

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

            var adminTenantIdClaim = User.FindFirst("tenant_id")?.Value;
            Guid? adminTenantId = null;
            if (!string.IsNullOrEmpty(adminTenantIdClaim) && Guid.TryParse(adminTenantIdClaim, out var atid))
                adminTenantId = atid;

            var dto = new CreateUserDto
            {
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Password = request.Password,
                Name = request.Name,
                GivenName = request.GivenName,
                FamilyName = request.FamilyName,
                Nickname = request.Nickname,
                TenantId = adminTenantId
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
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

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
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

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
        /// 彻底删除用户（管理员 - 物理删除，不可恢复，仅限已软删除用户）
        /// </summary>
        [HttpDelete("admin/users/{id}/permanent")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminHardDeleteUser(Guid id)
        {
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

            // 禁止彻底删除当前登录管理员本人
            if (GetCurrentUserId() == id)
            {
                return ApiResponseHelper.BadRequest<object>(this, "Cannot permanently delete the current administrator");
            }

            var result = await _userService.HardDeleteAsync(id);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Permanent delete failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("管理员彻底删除用户: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, "User permanently deleted");
        }

        /// <summary>
        /// 启用/禁用用户（管理员）
        /// </summary>
        [HttpPatch("admin/users/{id}/status")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminToggleUserStatus(Guid id, [FromBody] ToggleUserStatusRequest request)
        {
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

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
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

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
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<string>(this, "User not found");
            }

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

        /// <summary>
        /// 恢复已删除用户（管理员）
        /// </summary>
        [HttpPost("admin/users/{id}/restore")]
        [Authorize(Roles = "SuperAdmin,Admin")]
        public async Task<ActionResult<ApiResponse<object>>> AdminRestoreUser(Guid id)
        {
            var tenantUser = await GetTenantUserAsync(id);
            if (tenantUser == null)
            {
                return ApiResponseHelper.NotFound<object>(this, "User not found");
            }

            var result = await _userService.RestoreAsync(id);

            if (!result.IsSuccess)
            {
                return ApiResponseHelper.BadRequest<object>(
                    this,
                    "Restore failed",
                    result.GetErrorDictionary());
            }

            _logger.LogInformation("管理员恢复已删除用户: UserId={UserId}, Operator={Operator}", id, GetCurrentUserName());
            return ApiResponseHelper.Success<object>(this, null!, "User restored successfully");
        }

        #endregion

        #region ========== 辅助方法 ==========

        private Guid? GetCurrentUserId()
        {
            // OpenIddict Validation 将 JWT sub 存为 "sub" 而非 ClaimTypes.NameIdentifier
            var userIdStr = User.FindFirstValue(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject)
                         ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr)) return null;
            return Guid.Parse(userIdStr);
        }

        private string? GetCurrentUserName()
        {
            // OpenIddict Validation 使用 "name"/"email" 而非 ClaimTypes.Name/ClaimTypes.Email
            return User.FindFirstValue(OpenIddict.Abstractions.OpenIddictConstants.Claims.Name)
                ?? User.FindFirstValue(OpenIddict.Abstractions.OpenIddictConstants.Claims.Email)
                ?? User.FindFirstValue(ClaimTypes.Name)
                ?? User.FindFirstValue(ClaimTypes.Email);
        }

        /// <summary>
        /// 验证指定用户是否属于本租户，返回 UserDto 或 null
        /// </summary>
        private async Task<UserDto?> GetTenantUserAsync(Guid id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null) return null;

            // 验证管理员的 JWT tenant_id 与目标用户的 TenantId 匹配
            var adminTenantIdClaim = User.FindFirst("tenant_id")?.Value;
            if (string.IsNullOrEmpty(adminTenantIdClaim) || !Guid.TryParse(adminTenantIdClaim, out var adminTid))
            {
                _logger.LogWarning("GetTenantUserAsync: JWT 缺少 tenant_id 声明, 拒绝访问, UserId={Id}", id);
                return null;
            }

            if (user.TenantId != adminTid) return null;

            return user;
        }

        #endregion
    }
}
