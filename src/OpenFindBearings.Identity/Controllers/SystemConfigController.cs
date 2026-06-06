using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.SystemConfig;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 系统配置控制器 - 管理键值对配置（仅管理员）
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class SystemConfigController : ControllerBase
    {
        private readonly ISystemConfigService _configService;
        private readonly ILogger<SystemConfigController> _logger;

        public SystemConfigController(
            ISystemConfigService configService,
            ILogger<SystemConfigController> logger)
        {
            _configService = configService;
            _logger = logger;
        }

        #region ========== 配置查询 ==========

        /// <summary>
        /// 分页获取配置列表
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<PaginatedResult<SystemConfigDto>>>> GetList(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var result = await _configService.GetPagedAsync(page, pageSize);
            return Ok(ApiResponse<PaginatedResult<SystemConfigDto>>.SuccessResult(result));
        }

        /// <summary>
        /// 获取所有配置（字典格式）
        /// </summary>
        [HttpGet("dictionary")]
        public async Task<ActionResult<ApiResponse<Dictionary<string, object>>>> GetAllAsDictionary()
        {
            var configs = await _configService.GetAllAsDictionaryAsync();
            return Ok(ApiResponse<Dictionary<string, object>>.SuccessResult(configs));
        }

        /// <summary>
        /// 根据键获取配置值
        /// </summary>
        [HttpGet("{key}")]
        public async Task<ActionResult<ApiResponse<string>>> GetByKey(string key)
        {
            var exists = await _configService.ExistsAsync(key);
            if (!exists)
            {
                return NotFound(ApiResponse<string>.ErrorResult($"配置键 '{key}' 不存在", 404));
            }

            var value = await _configService.GetValueAsync<string>(key);
            var description = await _configService.GetDescriptionAsync(key);

            return Ok(ApiResponse<string>.SuccessResult(value ?? string.Empty, message: description));
        }

        /// <summary>
        /// 获取配置值（泛型版本，返回对象）
        /// </summary>
        [HttpGet("{key}/object")]
        public async Task<ActionResult<ApiResponse<object>>> GetByKeyAsObject(string key)
        {
            var exists = await _configService.ExistsAsync(key);
            if (!exists)
            {
                return NotFound(ApiResponse<object>.ErrorResult($"配置键 '{key}' 不存在", 404));
            }

            var value = await _configService.GetValueAsync<object>(key);
            var description = await _configService.GetDescriptionAsync(key);

            return Ok(ApiResponse<object>.SuccessResult(value ?? new object(), message: description));
        }

        #endregion

        #region ========== 配置管理 ==========

        /// <summary>
        /// 创建或更新配置
        /// </summary>
        [HttpPut("{key}")]
        public async Task<ActionResult<ApiResponse<object>>> SetValue(
            string key,
            [FromBody] SetSystemConfigRequest request)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return BadRequest(ApiResponse<object>.ErrorResult("配置键不能为空", 400));
            }

            if (request.Value == null)
            {
                return BadRequest(ApiResponse<object>.ErrorResult("配置值不能为空", 400));
            }

            await _configService.SetValueAsync(key, request.Value, request.Description);

            _logger.LogInformation("设置配置成功: Key={Key}, Operator={Operator}",
                key, User.Identity?.Name);

            var action = await _configService.ExistsAsync(key) ? "更新" : "创建";
            return Ok(ApiResponse<object>.SuccessResult(null!, $"配置{action}成功"));
        }

        /// <summary>
        /// 删除配置
        /// </summary>
        [HttpDelete("{key}")]
        public async Task<ActionResult<ApiResponse<object>>> Delete(string key)
        {
            var exists = await _configService.ExistsAsync(key);
            if (!exists)
            {
                return NotFound(ApiResponse<object>.ErrorResult($"配置键 '{key}' 不存在", 404));
            }

            var result = await _configService.DeleteAsync(key);
            if (!result)
            {
                return StatusCode(500, ApiResponse<object>.ErrorResult("删除失败", 500));
            }

            _logger.LogInformation("删除配置成功: Key={Key}, Operator={Operator}",
                key, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "配置删除成功"));
        }

        /// <summary>
        /// 更新配置描述
        /// </summary>
        [HttpPatch("{key}/description")]
        public async Task<ActionResult<ApiResponse<object>>> UpdateDescription(
            string key,
            [FromBody] UpdateConfigDescriptionRequest request)
        {
            var exists = await _configService.ExistsAsync(key);
            if (!exists)
            {
                return NotFound(ApiResponse<object>.ErrorResult($"配置键 '{key}' 不存在", 404));
            }

            await _configService.UpdateDescriptionAsync(key, request.Description);

            _logger.LogInformation("更新配置描述成功: Key={Key}, Operator={Operator}",
                key, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "配置描述更新成功"));
        }

        #endregion
    }
}
