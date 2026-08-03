using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SmsController : ControllerBase
    {
        private readonly ISmsCodeService _smsCodeService;
        private readonly ILogger<SmsController> _logger;

        public SmsController(
            ISmsCodeService smsCodeService,
            ILogger<SmsController> logger)
        {
            _smsCodeService = smsCodeService;
            _logger = logger;
        }

        [HttpPost("send-code")]
        [AllowAnonymous]
        public async Task<ActionResult<object>> SendCode([FromBody] SendSmsCodeRequest request)
        {
            if (!ModelState.IsValid)
            {
                return ApiResponseHelper.BadRequest<object>(this, "参数错误");
            }

            if (!PhoneNumberHelper.IsValid(request.Phone))
            {
                return ApiResponseHelper.BadRequest<object>(this, "手机号格式不正确");
            }

            var success = await _smsCodeService.SendAsync(request.Phone, request.Type);
            if (!success)
            {
                return ApiResponseHelper.BadRequest<object>(this, "发送过于频繁，请稍后再试");
            }

            _logger.LogInformation("验证码已发送: Phone={Phone}, Type={Type}", request.Phone, request.Type);

            return ApiResponseHelper.Success<object>(this, null!, "验证码已发送");
        }
    }
}
