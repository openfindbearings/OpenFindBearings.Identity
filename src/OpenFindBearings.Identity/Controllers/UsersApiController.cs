using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 用户查询 API（服务间调用）：供业务 API 按手机号/邮箱定位注册用户
    /// （如商户添加成员时判断对方是否已注册）。
    /// 改动说明：UsersController 是 MVC 管理面板（cookie+角色），无 REST 查询面，
    ///   业务 API 的 IdentityService 一直按 api/users/by-phone 调用（404 静默失败）；
    ///   本控制器补齐真实端点。集群内网服务（不经 Ingress 暴露），与 SmsController
    ///   同款 AllowAnonymous 先例。不动 OpenIddict/OAuth 任何配置。
    /// </summary>
    [ApiController]
    [Route("api/users")]
    [AllowAnonymous]
    public class UsersApiController : Controller
    {
        private readonly IUserService _userService;
        // 改动说明（v2.16.0）：注销链需要吊销令牌能力，注入既有 TokenRevocationService
        private readonly ITokenRevocationService _tokenRevocation;

        public UsersApiController(IUserService userService, ITokenRevocationService tokenRevocation)
        {
            _userService = userService;
            _tokenRevocation = tokenRevocation;
        }

        /// <summary>
        /// 按手机号查询注册用户（未注册返回 404）
        /// </summary>
        [HttpGet("by-phone")]
        public async Task<IActionResult> ByPhone([FromQuery] string phone, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(phone)) return BadRequest(new { message = "phone 参数必填" });

            var user = await _userService.GetByPhoneNumberAsync(phone, ct);
            if (user == null || !user.IsEnabled) return NotFound();

            return Ok(user);
        }

        /// <summary>
        /// 按邮箱查询注册用户（未注册返回 404）
        /// </summary>
        [HttpGet("by-email")]
        public async Task<IActionResult> ByEmail([FromQuery] string email, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(email)) return BadRequest(new { message = "email 参数必填" });

            var user = await _userService.GetByEmailAsync(email, ct);
            if (user == null || !user.IsEnabled) return NotFound();

            return Ok(user);
        }

        /// <summary>
        /// 注销账户（v2.16.0，供 API 用户自助注销链调用）：软删除（禁用+永久锁定+DeletedAt）
        /// 并吊销全部刷新令牌（全设备即时下线）。按 subject（AuthUserId）定位。
        /// </summary>
        [HttpPost("deactivate")]
        public async Task<IActionResult> Deactivate([FromBody] DeactivateUserRequest request, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(request.Subject))
                return BadRequest(new { message = "subject 必填" });

            if (!Guid.TryParse(request.Subject, out var userId))
                return BadRequest(new { message = "subject 非法" });

            var user = await _userService.GetByIdAsync(userId, ct);
            if (user == null) return NotFound(new { message = "用户不存在" });

            var result = await _userService.DeleteAsync(userId, ct);
            if (!result.IsSuccess)
                return BadRequest(new { message = "注销失败" });

            // 吊销全部刷新令牌：各设备下次刷新即失效，无法续期登录态
            await _tokenRevocation.RevokeAllRefreshTokensAsync(user.Id.ToString(), ct);
            return Ok(new { message = "账户已注销" });
        }

        /// <summary>
        /// 匿名化（v2.16.0，冷静期满由 API 定时任务调用）：清除个人身份信息
        /// （手机号/邮箱/用户名改匿名占位），配合软删除完成个保法删除义务。
        /// </summary>
        [HttpPost("anonymize")]
        public async Task<IActionResult> Anonymize([FromBody] DeactivateUserRequest request, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(request.Subject) || !Guid.TryParse(request.Subject, out var userId))
                return BadRequest(new { message = "subject 必填且为 GUID" });

            var result = await _userService.AnonymizeAsync(userId, ct);
            if (!result.IsSuccess) return NotFound(new { message = "用户不存在" });

            return Ok(new { message = "已匿名化" });
        }
    }

    /// <summary>
    /// 按 subject 定位用户的注销/匿名化请求体
    /// </summary>
    public record DeactivateUserRequest(string Subject);
}
