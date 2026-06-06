using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 修改密码请求
    /// </summary>
    public class ChangePasswordRequest
    {
        [Required(ErrorMessage = "当前密码不能为空")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

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
