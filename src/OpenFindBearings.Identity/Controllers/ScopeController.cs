using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Scope;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// Scope 管理控制器 - 管理 OAuth2/OIDC 作用域（仅管理员）
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class ScopeController : ControllerBase
    {
        private readonly IScopeService _scopeService;
        private readonly ILogger<ScopeController> _logger;

        public ScopeController(
            IScopeService scopeService,
            ILogger<ScopeController> logger)
        {
            _scopeService = scopeService;
            _logger = logger;
        }

        #region ========== Scope CRUD ==========

        /// <summary>
        /// 分页获取 Scope 列表
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<PaginatedResult<ScopeDto>>>> GetList(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? search = null)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var result = await _scopeService.GetPagedAsync(page, pageSize, search);
            return Ok(ApiResponse<PaginatedResult<ScopeDto>>.SuccessResult(result));
        }

        /// <summary>
        /// 获取所有 Scope（不分页，用于下拉选择等场景）
        /// </summary>
        [HttpGet("all")]
        public async Task<ActionResult<ApiResponse<IReadOnlyList<ScopeDto>>>> GetAll()
        {
            var scopes = await _scopeService.GetAllAsync();
            return Ok(ApiResponse<IReadOnlyList<ScopeDto>>.SuccessResult(scopes));
        }

        /// <summary>
        /// 根据名称获取 Scope
        /// </summary>
        [HttpGet("{name}")]
        public async Task<ActionResult<ApiResponse<ScopeDto>>> GetByName(string name)
        {
            var scope = await _scopeService.GetByNameAsync(name);
            if (scope == null)
            {
                return NotFound(ApiResponse<ScopeDto>.ErrorResult($"Scope '{name}' 不存在", 404));
            }

            return Ok(ApiResponse<ScopeDto>.SuccessResult(scope));
        }

        /// <summary>
        /// 创建新 Scope
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ApiResponse<ScopeDto>>> Create([FromBody] CreateScopeRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ApiResponse<ScopeDto>.ErrorResult("Invalid request data", 400));
            }

            var dto = new CreateScopeDto
            {
                Name = request.Name,
                DisplayName = request.DisplayName,
                Description = request.Description,
                Resources = request.Resources ?? new List<string>()
            };

            var result = await _scopeService.CreateAsync(dto);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<ScopeDto>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "创建失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("创建 Scope 成功: Name={Name}, Operator={Operator}",
                result.Data?.Name, User.Identity?.Name);

            return CreatedAtAction(
                nameof(GetByName),
                new { name = result.Data!.Name },
                ApiResponse<ScopeDto>.SuccessResult(result.Data, "Scope 创建成功"));
        }

        /// <summary>
        /// 更新 Scope
        /// </summary>
        [HttpPut("{name}")]
        public async Task<ActionResult<ApiResponse<object>>> Update(
            string name,
            [FromBody] UpdateScopeRequest request)
        {
            var dto = new UpdateScopeDto
            {
                DisplayName = request.DisplayName,
                Description = request.Description
            };

            var result = await _scopeService.UpdateAsync(name, dto);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<object>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "更新失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("更新 Scope 成功: Name={Name}, Operator={Operator}",
                name, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "Scope 更新成功"));
        }

        /// <summary>
        /// 删除 Scope
        /// </summary>
        [HttpDelete("{name}")]
        public async Task<ActionResult<ApiResponse<object>>> Delete(string name)
        {
            var result = await _scopeService.DeleteAsync(name);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<object>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "删除失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("删除 Scope 成功: Name={Name}, Operator={Operator}",
                name, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "Scope 删除成功"));
        }

        #endregion
    }
}
