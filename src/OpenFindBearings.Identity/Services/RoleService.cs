using Microsoft.AspNetCore.Identity;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Models.DTOs.Role;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 角色服务实现
    /// </summary>
    public class RoleService : IRoleService
    {
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly UserManager<OidcUser> _userManager;
        private readonly IAuditLogRepository _auditLogRepo;

        public RoleService(
            RoleManager<IdentityRole<Guid>> roleManager,
            UserManager<OidcUser> userManager,
            IAuditLogRepository auditLogRepo)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _auditLogRepo = auditLogRepo;
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<RoleDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default)
        {
            var query = _roleManager.Roles.AsQueryable();

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(r => r.Name!.Contains(search));
            }

            var total = await query.CountAsync(ct);
            var roles = await query
                .OrderBy(r => r.Name)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            var dtos = new List<RoleDto>();
            foreach (var role in roles)
            {
                var userCount = await _userManager.GetUsersInRoleAsync(role.Name!);
                dtos.Add(new RoleDto
                {
                    Id = role.Id,
                    Name = role.Name!,
                    UserCount = userCount.Count,
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }

            return new PaginatedResult<RoleDto>(dtos, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<RoleDto>> GetAllAsync(CancellationToken ct = default)
        {
            var roles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync(ct);
            return roles.Select(r => new RoleDto
            {
                Id = r.Id,
                Name = r.Name!,
                UserCount = 0
            }).ToList();
        }

        /// <inheritdoc/>
        public async Task<RoleDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
        {
            var role = await _roleManager.FindByIdAsync(id.ToString());
            if (role == null) return null;

            var userCount = await _userManager.GetUsersInRoleAsync(role.Name!);
            return new RoleDto
            {
                Id = role.Id,
                Name = role.Name!,
                UserCount = userCount.Count,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <inheritdoc/>
        public async Task<RoleDto?> GetByNameAsync(string name, CancellationToken ct = default)
        {
            var role = await _roleManager.FindByNameAsync(name);
            if (role == null) return null;

            var userCount = await _userManager.GetUsersInRoleAsync(role.Name!);
            return new RoleDto
            {
                Id = role.Id,
                Name = role.Name!,
                UserCount = userCount.Count,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <inheritdoc/>
        public async Task<bool> ExistsAsync(string name, CancellationToken ct = default)
        {
            return await _roleManager.RoleExistsAsync(name);
        }

        /// <inheritdoc/>
        public async Task<ServiceResult<RoleDto>> CreateAsync(string name, CancellationToken ct = default)
        {
            if (await _roleManager.RoleExistsAsync(name))
            {
                return ServiceResult<RoleDto>.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "RoleAlreadyExists",
                        Description = $"角色 '{name}' 已存在"
                    }
                });
            }

            var role = new IdentityRole<Guid> { Name = name };
            var result = await _roleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                return ServiceResult<RoleDto>.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogRoleActionAsync(null, "System", "CreateRole", role.Id.ToString(), null, true, ct);

            return ServiceResult<RoleDto>.Success(new RoleDto
            {
                Id = role.Id,
                Name = role.Name!,
                UserCount = 0
            });
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken ct = default)
        {
            var role = await _roleManager.FindByIdAsync(id.ToString());
            if (role == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "RoleNotFound",
                        Description = "角色不存在"
                    }
                });
            }

            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
            if (usersInRole.Any())
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "RoleHasUsers",
                        Description = $"角色 '{role.Name}' 仍有 {usersInRole.Count} 个用户在使用，无法删除"
                    }
                });
            }

            var result = await _roleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                return ServiceResult.Failure(result.Errors.Select(e => new ServiceError
                {
                    Code = e.Code,
                    Description = e.Description
                }).ToArray());
            }

            await _auditLogRepo.LogRoleActionAsync(null, "System", "DeleteRole", role.Id.ToString(), null, true, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<int> GetUserCountAsync(string roleName, CancellationToken ct = default)
        {
            var users = await _userManager.GetUsersInRoleAsync(roleName);
            return users.Count;
        }
    }
}
