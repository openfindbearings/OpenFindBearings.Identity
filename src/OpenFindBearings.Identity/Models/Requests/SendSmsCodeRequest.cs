using System.ComponentModel.DataAnnotations;
using OpenFindBearings.Identity.Constants;

namespace OpenFindBearings.Identity.Models.Requests
{
    public class SendSmsCodeRequest
    {
        [Required(ErrorMessage = "手机号不能为空")]
        public string Phone { get; set; } = string.Empty;

        [Required(ErrorMessage = "验证码类型不能为空")]
        public string Type { get; set; } = SmsCodeTypeConstants.Login;
    }
}
