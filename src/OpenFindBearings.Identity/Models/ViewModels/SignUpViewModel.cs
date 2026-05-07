using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.ViewModels
{
    /// <summary>
    /// 注册视图模型
    /// </summary>
    public class SignUpViewModel
    {
        [Required(ErrorMessage = "请输入用户名、邮箱或电话号码")]
        [Display(Name = "用户名/邮箱/电话号码")]
        public string Account { get; set; } = string.Empty;

        [Required(ErrorMessage = "请输入密码")]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        //[Display(Name = "Password")]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        //[Display(Name = "Confirm password")]
        [Display(Name = "请确认密码")]
        //[Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        [Compare("Password", ErrorMessage = "两次输入的密码不一致")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
