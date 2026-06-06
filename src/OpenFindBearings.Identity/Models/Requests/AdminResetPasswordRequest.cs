using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 管理员重置密码请求
    /// </summary>
    public class AdminResetPasswordRequest
    {
        [Required(ErrorMessage = "新密码不能为空")]
        [MinLength(6, ErrorMessage = "密码长度至少6位")]
        public string NewPassword { get; set; } = string.Empty;
    }
}
