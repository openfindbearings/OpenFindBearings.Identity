using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.AuditLog;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Validation.AspNetCore;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 审计日志控制器 - 查询和清理审计日志（仅管理员）
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "SuperAdmin,Admin")]
    public class AuditLogController : ControllerBase
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<AuditLogController> _logger;

        public AuditLogController(
            IAuditLogService auditLogService,
            ILogger<AuditLogController> logger)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        #region ========== 查询 ==========

        /// <summary>
        /// 分页获取审计日志
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<PaginatedResult<AuditLogDto>>>> GetList(
            [FromQuery] AuditLogQueryRequest request)
        {
            if (request.Page < 1) request.Page = 1;
            if (request.PageSize < 1) request.PageSize = 20;
            if (request.PageSize > 100) request.PageSize = 100;

            var result = await _auditLogService.GetPagedAsync(
                request.Page,
                request.PageSize,
                request.Action,
                request.ResourceType,
                request.StartDate,
                request.EndDate);

            return Ok(ApiResponse<PaginatedResult<AuditLogDto>>.SuccessResult(result));
        }

        /// <summary>
        /// 获取审计日志详情
        /// </summary>
        [HttpGet("{id:guid}")]
        public async Task<ActionResult<ApiResponse<AuditLogDto>>> GetById(Guid id)
        {
            var log = await _auditLogService.GetByIdAsync(id);
            if (log == null)
            {
                return NotFound(ApiResponse<AuditLogDto>.ErrorResult($"日志 '{id}' 不存在", 404));
            }

            return Ok(ApiResponse<AuditLogDto>.SuccessResult(log));
        }

        /// <summary>
        /// 获取今日日志数量
        /// </summary>
        [HttpGet("today-count")]
        public async Task<ActionResult<ApiResponse<int>>> GetTodayCount()
        {
            var count = await _auditLogService.GetTodayCountAsync();
            return Ok(ApiResponse<int>.SuccessResult(count));
        }

        /// <summary>
        /// 获取最近的操作日志
        /// </summary>
        [HttpGet("recent")]
        public async Task<ActionResult<ApiResponse<IReadOnlyList<AuditLogDto>>>> GetRecent([FromQuery] int take = 20)
        {
            if (take < 1) take = 20;
            if (take > 100) take = 100;

            var logs = await _auditLogService.GetRecentAsync(take);
            return Ok(ApiResponse<IReadOnlyList<AuditLogDto>>.SuccessResult(logs));
        }

        /// <summary>
        /// 获取指定用户的日志
        /// </summary>
        [HttpGet("user/{userId:guid}")]
        public async Task<ActionResult<ApiResponse<IReadOnlyList<AuditLogDto>>>> GetByUserId(
            Guid userId,
            [FromQuery] int take = 50)
        {
            if (take < 1) take = 50;
            if (take > 200) take = 200;

            var logs = await _auditLogService.GetByUserIdAsync(userId, take);
            return Ok(ApiResponse<IReadOnlyList<AuditLogDto>>.SuccessResult(logs));
        }

        #endregion

        #region ========== 统计 ==========

        /// <summary>
        /// 获取操作类型统计
        /// </summary>
        [HttpGet("statistics/actions")]
        public async Task<ActionResult<ApiResponse<Dictionary<string, int>>>> GetActionStatistics()
        {
            var result = await _auditLogService.GetPagedAsync(1, 1000);
            var statistics = result.Items
                .GroupBy(x => x.Action)
                .ToDictionary(g => g.Key, g => g.Count());

            return Ok(ApiResponse<Dictionary<string, int>>.SuccessResult(statistics));
        }

        #endregion
    }
}
