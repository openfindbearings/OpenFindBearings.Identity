using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 创建用户请求
    /// </summary>
    public class CreateUserRequest
    {
        /// <summary>
        /// 用户名（必填，3-50字符）
        /// </summary>
        [Required(ErrorMessage = "用户名不能为空")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "用户名长度必须在3-50字符之间")]
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// 电子邮箱（必填）
        /// </summary>
        [Required(ErrorMessage = "邮箱不能为空")]
        [EmailAddress(ErrorMessage = "邮箱格式不正确")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// 密码（必填，6-100字符）
        /// </summary>
        [Required(ErrorMessage = "密码不能为空")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "密码长度必须在6-100字符之间")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// 手机号（可选）
        /// </summary>
        [Phone(ErrorMessage = "手机号格式不正确")]
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// 全名
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// 名
        /// </summary>
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓
        /// </summary>
        public string? FamilyName { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; set; }
    }
}
