using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Client;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 客户端管理控制器 - 管理 OAuth2/OIDC 客户端（仅管理员）
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class ApplicationController : ControllerBase
    {
        private readonly IClientService _clientService;
        private readonly ILogger<ApplicationController> _logger;

        public ApplicationController(
            IClientService clientService,
            ILogger<ApplicationController> logger)
        {
            _clientService = clientService;
            _logger = logger;
        }

        #region ========== 客户端 CRUD ==========

        /// <summary>
        /// 分页获取客户端列表
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<PaginatedResult<ClientDto>>>> GetList(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? search = null)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var result = await _clientService.GetPagedAsync(page, pageSize, search);
            return Ok(ApiResponse<PaginatedResult<ClientDto>>.SuccessResult(result));
        }

        /// <summary>
        /// 根据 ClientId 获取客户端
        /// </summary>
        [HttpGet("{clientId}")]
        public async Task<ActionResult<ApiResponse<ClientDto>>> GetByClientId(string clientId)
        {
            var client = await _clientService.GetByClientIdAsync(clientId);
            if (client == null)
            {
                return NotFound(ApiResponse<ClientDto>.ErrorResult($"客户端 '{clientId}' 不存在", 404));
            }

            return Ok(ApiResponse<ClientDto>.SuccessResult(client));
        }

        /// <summary>
        /// 创建新客户端
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ApiResponse<ClientDto>>> Create([FromBody] CreateClientRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ApiResponse<ClientDto>.ErrorResult("Invalid request data", 400));
            }

            var dto = new CreateClientDto
            {
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                DisplayName = request.DisplayName,
                RedirectUri = request.RedirectUri,
                Scopes = request.Scopes ?? new List<string>()
            };

            var result = await _clientService.CreateAsync(dto);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<ClientDto>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "创建失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("创建客户端成功: ClientId={ClientId}, Operator={Operator}",
                result.Data?.ClientId, User.Identity?.Name);

            return CreatedAtAction(
                nameof(GetByClientId),
                new { clientId = result.Data!.ClientId },
                ApiResponse<ClientDto>.SuccessResult(result.Data, "客户端创建成功"));
        }

        /// <summary>
        /// 更新客户端
        /// </summary>
        [HttpPut("{clientId}")]
        public async Task<ActionResult<ApiResponse<object>>> Update(
            string clientId,
            [FromBody] UpdateClientRequest request)
        {
            var dto = new UpdateClientDto
            {
                DisplayName = request.DisplayName
            };

            var result = await _clientService.UpdateAsync(clientId, dto);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<object>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "更新失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("更新客户端成功: ClientId={ClientId}, Operator={Operator}",
                clientId, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "客户端更新成功"));
        }

        /// <summary>
        /// 删除客户端
        /// </summary>
        [HttpDelete("{clientId}")]
        public async Task<ActionResult<ApiResponse<object>>> Delete(string clientId)
        {
            var result = await _clientService.DeleteAsync(clientId);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<object>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "删除失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("删除客户端成功: ClientId={ClientId}, Operator={Operator}",
                clientId, User.Identity?.Name);

            return Ok(ApiResponse<object>.SuccessResult(null!, "客户端删除成功"));
        }

        /// <summary>
        /// 重新生成客户端密钥
        /// </summary>
        [HttpPost("{clientId}/regenerate-secret")]
        public async Task<ActionResult<ApiResponse<string>>> RegenerateSecret(string clientId)
        {
            var result = await _clientService.RegenerateSecretAsync(clientId);

            if (!result.IsSuccess)
            {
                return BadRequest(ApiResponse<string>.ErrorResult(
                    result.Errors.FirstOrDefault()?.Description ?? "重新生成密钥失败",
                    400,
                    result.GetErrorDictionary()));
            }

            _logger.LogInformation("重新生成客户端密钥成功: ClientId={ClientId}, Operator={Operator}",
                clientId, User.Identity?.Name);

            return Ok(ApiResponse<string>.SuccessResult(result.Data!, "密钥重新生成成功"));
        }

        #endregion
    }
}
