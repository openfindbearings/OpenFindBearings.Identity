using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Role;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 角色管理控制器 - 管理用户角色（仅管理员）
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class RoleController : ControllerBase
    {
        private readonly IRoleService _roleService;
        private readonly ILogger<RoleController> _logger;

        public RoleController(
            IRoleService roleService,
            ILogger<RoleController> logger)
        {
            _roleService = roleService;
            _logger = logger;
        }

        #region ========== 角色查询 ==========

        /// <summary>
        /// 分页获取角色列表
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<PaginatedResult<RoleDto>>>> GetList(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? search = null)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var result = await _roleService.GetPagedAsync(page, pageSize, search);
            return Ok(ApiResponse<PaginatedResult<RoleDto>>.SuccessResult(result));
        }

        /// <summary>
        /// 获取所有角色（不分页，用于下拉选择等场景）
        /// </summary>
        [HttpGet("all")]
        public async Task<ActionResult<ApiResponse<IReadOnlyList<RoleDto>>>> GetAll()
        {
            var roles = await _roleService.GetAllAsync();
            return Ok(ApiResponse<IReadOnlyList<RoleDto>>.SuccessResult(roles));
        }

        /// <summary>
        /// 根据 ID 获取角色
        /// </summary>
        [HttpGet("{id:guid}")]
        public async Task<ActionResult<ApiResponse<RoleDto>>> GetById(Guid id)
        {
            var role = await _roleService.GetByIdAsync(id);
            if (role == null)
            {
                return NotFound(ApiResponse<RoleDto>.ErrorResult($"角色 ID '{id}' 不存在", 404));
            }

            return Ok(ApiResponse<RoleDto>.SuccessResult(role));
        }

        /// <summary>
        /// 根据名称获取角色
        /// </summary>
        [HttpGet("by-name/{name}")]
        public async Task<ActionResult<ApiResponse<RoleDto>>> GetByName(string name)
        {
            var role = await _roleService.GetByNameAsync(name);
            if (role == null)
            {
                return NotFound(ApiResponse<RoleDto>.ErrorResult($"角色 '{name}' 不存在", 404));
            }

            return Ok(ApiResponse<RoleDto>.SuccessResult(role));
        }

        #endregion

        #region ========== 角色 CRUD ==========

        /// <summary>
        /// 创建新角色
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ApiResponse<RoleDto>>> Create([FromBody] CreateRoleRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ApiResponse<RoleDto>.ErrorResult("Invalid request data", 400));
            }

            var result = await _roleService.CreateAsync(request.Name);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<RoleDto>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "创建失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("创建角色成功: Name={Name}, Operator={Operator}",
                result.Data?.Name, User.Identity?.Name);

            return CreatedAtAction(
                nameof(GetById),
                new { id = result.Data!.Id },
                ApiResponse<RoleDto>.SuccessResult(result.Data, "角色创建成功"));
        }

        /// <summary>
        /// 删除角色
        /// </summary>
        [HttpDelete("{id:guid}")]
        public async Task<ActionResult<ApiResponse<object>>> Delete(Guid id)
        {
            var result = await _roleService.DeleteAsync(id);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<object>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "删除失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("删除角色成功: RoleId={RoleId}, Operator={Operator}",
                id, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "角色删除成功"));
        }

        #endregion
    }
}
