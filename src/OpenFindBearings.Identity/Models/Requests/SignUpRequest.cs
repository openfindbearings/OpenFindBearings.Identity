using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 注册请求
    /// </summary>
    public class SignUpRequest
    {
        /// <summary>
        /// 账号（可以是用户名/邮箱/手机号）
        /// </summary>
        [Required(ErrorMessage = "账号不能为空")]
        public string Account { get; set; } = string.Empty;

        /// <summary>
        /// 密码
        /// </summary>
        [Required(ErrorMessage = "密码不能为空")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "密码长度必须在6-100字符之间")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// 确认密码
        /// </summary>
        [Required(ErrorMessage = "请确认密码")]
        [Compare("Password", ErrorMessage = "两次输入的密码不一致")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;

        /// <summary>
        /// 邀请码
        /// </summary>
        public string? InviteCode { get; set; }

        /// <summary>
        /// 是否同意条款
        /// </summary>
        [Range(typeof(bool), "true", "true", ErrorMessage = "请同意用户协议")]
        public bool AgreeTerms { get; set; }

        /// <summary>
        /// 租户名称（realm），如 "openfindbearings"。手机 App 自行硬编码
        /// </summary>
        [Required(ErrorMessage = "租户标识不能为空")]
        public string Realm { get; set; } = string.Empty;
    }
}
