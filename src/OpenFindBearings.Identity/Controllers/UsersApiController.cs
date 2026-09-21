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

        public UsersApiController(IUserService userService)
        {
            _userService = userService;
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
    }
}
