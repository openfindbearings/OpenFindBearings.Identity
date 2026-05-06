using Microsoft.AspNetCore.Identity;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Enums;
using OpenFindBearings.Identity.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Models.DTOs.Requests;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 用户服务实现
    /// </summary>
    public class UserService : IUserService
    {
        private readonly UserManager<OidcUser> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly IAuditLogRepository _auditLogRepo;
        private readonly IPasswordHasher<OidcUser> _passwordHasher;

        public UserService(
            UserManager<OidcUser> userManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            IAuditLogRepository auditLogRepo,
            IPasswordHasher<OidcUser> passwordHasher)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _auditLogRepo = auditLogRepo;
            _passwordHasher = passwordHasher;
        }

        #region 查询

        /// <inheritdoc/>
        public async Task<PaginatedResult<UserDto>> GetPagedAsync(int page, int size, string? search = null, UserStatusFilter? status = null, CancellationToken ct = default)
        {
            var query = _userManager.Users.Where(u => u.IsActive);

            // 搜索过滤
            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(u => u.UserName!.Contains(search) ||
                                         (u.Email != null && u.Email.Contains(search)) ||
                                         (u.Name != null && u.Name.Contains(search)));
            }

            // 状态过滤
            if (status.HasValue)
            {
                query = status.Value switch
                {
                    UserStatusFilter.Enabled => query.Where(u => u.IsEnabled && (!u.LockoutEnabled || !u.LockoutEnd.HasValue || u.LockoutEnd < DateTimeOffset.UtcNow)),
                    UserStatusFilter.Disabled => query.Where(u => !u.IsEnabled),
                    UserStatusFilter.Locked => query.Where(u => u.LockoutEnabled && u.LockoutEnd.HasValue && u.LockoutEnd > DateTimeOffset.UtcNow),
                    _ => query
                };
            }

            var total = await query.CountAsync(ct);
            var users = await query
                .OrderByDescending(u => u.CreatedAt)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            var dtos = users.Select(MapToDto).ToList();
            return new PaginatedResult<UserDto>(dtos, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            return user != null ? MapToDto(user) : null;
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByUsernameAsync(string username, CancellationToken ct = default)
        {
            var user = await _userManager.FindByNameAsync(username);
            return user != null ? MapToDto(user) : null;
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByEmailAsync(string email, CancellationToken ct = default)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return user != null ? MapToDto(user) : null;
        }

        /// <inheritdoc/>
        public async Task<int> GetCountAsync(CancellationToken ct = default)
        {
            return await _userManager.Users.CountAsync(u => u.IsActive, ct);
        }

        #endregion

        #region 创建/更新/删除

        /// <inheritdoc/>
        public async Task<ServiceResult<UserDto>> CreateAsync(CreateUserRequest request, CancellationToken ct = default)
        {
            //var user = new OidcUser
            //{
            //    UserName = request.UserName,
            //    Email = request.Email,
            //    PhoneNumber = request.PhoneNumber,
            //    Name = request.Name,
            //    GivenName = request.GivenName,
            //    FamilyName = request.FamilyName,
            //    Nickname = request.Nickname,
            //    IsEnabled = true,
            //    CreatedAt = DateTimeOffset.UtcNow
            //};

            var user = OidcUser.Create(
                userName: request.UserName,
                email: request.Email,
                phoneNumber: request.PhoneNumber,
                name: request.Name,
                givenName: request.GivenName,
                familyName: request.FamilyName);

            // 然后再用业务方法设置其他属性
            if (!string.IsNullOrEmpty(request.Nickname))
            {
                user.UpdateProfile(nickname: request.Nickname);
            }

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return ServiceResult<UserDto>.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            // 修复：正确的参数顺序
            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "CreateUser", user.Id.ToString(), null, true, null, ct);

            return ServiceResult<UserDto>.Success(MapToDto(user));
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> UpdateAsync(Guid id, UpdateUserRequest request, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.UpdateProfile(request.Name, request.GivenName, request.FamilyName, request.Nickname, request.PictureUrl, request.WebsiteUrl);
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "UpdateUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.SoftDelete();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "DeleteUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> RestoreAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.Restore();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "RestoreUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> EnableAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.Enable();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "EnableUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> DisableAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.Disable();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "DisableUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> UnlockAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            user.Unlock();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "UnlockUser", user.Id.ToString(), null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult<string>> ResetPasswordAsync(Guid id, string newPassword, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult<string>.Failure("用户不存在");
            }

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, newPassword);

            if (!result.Succeeded)
            {
                return ServiceResult<string>.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "ResetPassword", user.Id.ToString(), null, true, null, ct);
            return ServiceResult<string>.Success("密码重置成功");
        }

        #endregion

        #region 角色管理

        /// <inheritdoc/>
        public async Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return Array.Empty<string>();
            }
            var roles = await _userManager.GetRolesAsync(user);
            return roles.ToList().AsReadOnly();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> AddToRoleAsync(Guid userId, string role, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            if (!await _roleManager.RoleExistsAsync(role))
            {
                return ServiceResult.Failure($"角色 '{role}' 不存在");
            }

            var result = await _userManager.AddToRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "AddToRole", role, null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> RemoveFromRoleAsync(Guid userId, string role, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            var result = await _userManager.RemoveFromRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "RemoveFromRole", role, null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> SetRolesAsync(Guid userId, string[] roles, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
            if (!removeResult.Succeeded)
            {
                return ServiceResult.Failure(removeResult.Errors.Select(e => e.Description).ToArray());
            }

            var addResult = await _userManager.AddToRolesAsync(user, roles);
            if (!addResult.Succeeded)
            {
                return ServiceResult.Failure(addResult.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "SetRoles", string.Join(",", roles), null, true, null, ct);
            return ServiceResult.Success();
        }

        #endregion

        #region 声明管理

        /// <inheritdoc/>
        public async Task<IReadOnlyList<(string Type, string Value)>> GetClaimsAsync(Guid userId, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return Array.Empty<(string, string)>();
            }

            var claims = await _userManager.GetClaimsAsync(user);
            return claims.Select(c => (c.Type, c.Value)).ToList();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> AddClaimAsync(Guid userId, string claimType, string claimValue, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            var result = await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(claimType, claimValue));
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "AddClaim", $"{claimType}:{claimValue}", null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> RemoveClaimAsync(Guid userId, string claimType, string claimValue, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ServiceResult.Failure("用户不存在");
            }

            var claim = new System.Security.Claims.Claim(claimType, claimValue);
            var result = await _userManager.RemoveClaimAsync(user, claim);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => e.Description).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "RemoveClaim", $"{claimType}:{claimValue}", null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<bool> CheckCanLoginAsync(Guid userId, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null) return false;
            return user.IsAvailable();
        }

        /// <inheritdoc/>
        public async Task<bool> CheckPasswordAsync(Guid userId, string password, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null) return false;
            return await _userManager.CheckPasswordAsync(user, password);
        }

        /// <inheritdoc/>
        public async Task RecordLoginSuccessAsync(Guid userId, string? ip = null, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user != null)
            {
                user.RecordSuccessfulLogin(ip);
                await _userManager.UpdateAsync(user);
            }
        }

        /// <inheritdoc/>
        public async Task RecordLoginFailureAsync(Guid userId, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user != null)
            {
                user.RecordFailedLogin();
                await _userManager.UpdateAsync(user);
            }
        }

        #endregion

        #region 私有方法

        /// <summary>
        /// 实体转DTO
        /// </summary>
        private static UserDto MapToDto(OidcUser user)
        {
            return new UserDto
            {
                Id = user.Id,
                Sub = user.Sub,
                UserName = user.UserName,
                Email = user.Email,
                EmailVerified = user.EmailVerified,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberVerified = user.PhoneNumberVerified,
                Name = user.Name,
                GivenName = user.GivenName,
                FamilyName = user.FamilyName,
                Nickname = user.Nickname,
                PictureUrl = user.PictureUrl,
                WebsiteUrl = user.WebsiteUrl,
                Gender = user.Gender,
                Birthdate = user.Birthdate,
                Locale = user.Locale,
                ZoneInfo = user.ZoneInfo,
                Address = user.Address,
                IsEnabled = user.IsEnabled,
                IsActive = user.IsActive,
                LastLoginAt = user.LastLoginAt,
                LastLoginIp = user.LastLoginIp,
                LastLoginDevice = user.LastLoginDevice,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };
        }

        #endregion
    }
}
