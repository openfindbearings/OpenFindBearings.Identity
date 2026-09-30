using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 修改密码请求
    /// </summary>
    public class ChangePasswordRequest
    {
        /// <summary>
        /// 当前密码。
        /// 改动说明（短信登录上线）：去掉 [Required]——验证码登录自动注册的用户没有密码，
        /// 首次设置密码必须允许留空；已设密码的账号由服务端校验（留空视为错误）。
        /// 改动说明（验证码改密）：移动端 API 端（AccountController）已改走 VerifyCode 验证、
        /// 不再读此字段；本网页端 ProfileController 仍验旧密码继续使用——
        /// 故不在模型级加 [Required]，必填由各端点自行把关（共用模型互不牵连）。
        /// </summary>
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

        /// <summary>
        /// 短信验证码（移动端改密用，type=reset_password）。
        /// 改动说明（验证码改密）：移动端改密由"验旧密码"改为验证码验证——
        /// 验证码注册用户多数无密码，且忘旧密码时旧方案无路可走；账号本就锚定手机号。
        /// </summary>
        public string VerifyCode { get; set; } = string.Empty;

        [Required(ErrorMessage = "新密码不能为空")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "密码长度必须在6-100字符之间")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "请确认新密码")]
        [Compare("NewPassword", ErrorMessage = "两次输入的新密码不一致")]
        [DataType(DataType.Password)]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
