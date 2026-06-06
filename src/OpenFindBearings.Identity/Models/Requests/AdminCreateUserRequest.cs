using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 管理员创建用户请求
    /// </summary>
    public class AdminCreateUserRequest
    {
        [Required(ErrorMessage = "用户名不能为空")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "邮箱不能为空")]
        [EmailAddress(ErrorMessage = "邮箱格式不正确")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "密码不能为空")]
        [MinLength(6, ErrorMessage = "密码长度至少6位")]
        public string Password { get; set; } = string.Empty;

        public string? PhoneNumber { get; set; }
        public string? Name { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
        public string? Nickname { get; set; }
        public List<string>? Roles { get; set; }
    }
}
