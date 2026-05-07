using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.User;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Enums;
using OpenFindBearings.Identity.Services.Interfaces;

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
        public async Task<PaginatedResult<UserDto>> GetPagedAsync(
     int page,
     int size,
     string? search = null,
     UserStatusFilter? status = null,
     string? role = null,
     DateTimeOffset? dateFrom = null,
     DateTimeOffset? dateTo = null,
     DateTimeOffset? lastLoginFrom = null,
     DateTimeOffset? lastLoginTo = null,
     CancellationToken ct = default)
        {
            var query = _userManager.Users.Where(u => u.IsActive);

            // 搜索过滤（用户名/邮箱/姓名/手机号）
            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(u => u.UserName!.Contains(search) ||
                                         (u.Email != null && u.Email.Contains(search)) ||
                                         (u.Name != null && u.Name.Contains(search)) ||
                                         (u.PhoneNumber != null && u.PhoneNumber.Contains(search)));
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

            // 角色过滤（需要先查出用户，再过滤角色，因为角色不在 Users 表中）
            var users = await query.ToListAsync(ct);

            if (!string.IsNullOrEmpty(role))
            {
                var filteredUsers = new List<OidcUser>();
                foreach (var user in users)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    if (roles.Contains(role))
                    {
                        filteredUsers.Add(user);
                    }
                }
                users = filteredUsers;
            }
            else
            {
                users = users.ToList();
            }

            // 注册时间范围过滤
            if (dateFrom.HasValue)
            {
                users = users.Where(u => u.CreatedAt >= dateFrom.Value).ToList();
            }
            if (dateTo.HasValue)
            {
                users = users.Where(u => u.CreatedAt <= dateTo.Value).ToList();
            }

            // 最后登录时间范围过滤
            if (lastLoginFrom.HasValue)
            {
                users = users.Where(u => u.LastLoginAt.HasValue && u.LastLoginAt >= lastLoginFrom.Value).ToList();
            }
            if (lastLoginTo.HasValue)
            {
                users = users.Where(u => u.LastLoginAt.HasValue && u.LastLoginAt <= lastLoginTo.Value).ToList();
            }

            var total = users.Count;
            var pagedUsers = users
                .OrderByDescending(u => u.CreatedAt)
                .Skip((page - 1) * size)
                .Take(size)
                .ToList();

            var dtos = pagedUsers.Select(u => u.ToDto()).ToList();
            return new PaginatedResult<UserDto>(dtos, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            return user != null ? user.ToDto() : null;
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByUsernameAsync(string username, CancellationToken ct = default)
        {
            var user = await _userManager.FindByNameAsync(username);
            return user != null ? user.ToDto() : null;
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByEmailAsync(string email, CancellationToken ct = default)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return user != null ? user.ToDto() : null;
        }

        /// <inheritdoc/>
        public async Task<UserDto?> GetByPhoneNumberAsync(string phoneNumber, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                return null;

            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber && u.IsActive, ct);

            return user != null ? user.ToDto() : null;
        }

        /// <inheritdoc/>
        public async Task<int> GetCountAsync(CancellationToken ct = default)
        {
            return await _userManager.Users.CountAsync(u => u.IsActive, ct);
        }

        #endregion

        #region 创建/更新/删除

        /// <inheritdoc/>
        public async Task<ServiceResult<UserDto>> CreateAsync(CreateUserDto request, CancellationToken ct = default)
        {
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
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
            }

            // 修复：正确的参数顺序
            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "CreateUser", user.Id.ToString(), null, true, null, ct);

            return ServiceResult<UserDto>.Success(user.ToDto());
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> UpdateAsync(Guid id, UpdateUserDto request, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.UpdateProfile(request.Name, request.GivenName, request.FamilyName, request.Nickname, request.PictureUrl, request.WebsiteUrl);
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.SoftDelete();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.Restore();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.Enable();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.Disable();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            user.Unlock();
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray();

                return ServiceResult<UserDto>.Failure(errors);
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
                return (ServiceResult<string>)ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });
            }

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, newPassword);

            if (!result.Succeeded)
            {
                return ServiceResult<string>.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });

            if (!await _roleManager.RoleExistsAsync(role))
                return ServiceResult.Failure(new ServiceError { Code = "RoleNotFound", Description = $"角色 '{role}' 不存在" });

            var result = await _userManager.AddToRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "AddToRole", role, null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> RemoveFromRoleAsync(Guid userId, string role, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });

            var result = await _userManager.RemoveFromRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "RemoveFromRole", role, null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> SetRolesAsync(Guid userId, string[] roles, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });

            var currentRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
            if (!removeResult.Succeeded)
            {
                return ServiceResult.Failure(removeResult.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            var addResult = await _userManager.AddToRolesAsync(user, roles);
            if (!addResult.Succeeded)
            {
                return ServiceResult.Failure(addResult.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
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
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });

            var result = await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(claimType, claimValue));
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "AddClaim", $"{claimType}:{claimValue}", null, true, null, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> RemoveClaimAsync(Guid userId, string claimType, string claimValue, CancellationToken ct = default)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return ServiceResult.Failure(new ServiceError { Code = "UserNotFound", Description = "用户不存在" });

            var claim = new System.Security.Claims.Claim(claimType, claimValue);
            var result = await _userManager.RemoveClaimAsync(user, claim);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogUserActionAsync(user.Id, user.UserName, "RemoveClaim", $"{claimType}:{claimValue}", null, true, null, ct);
            return ServiceResult.Success();
        }

        #endregion

        #region 登录辅助

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
    }
}
