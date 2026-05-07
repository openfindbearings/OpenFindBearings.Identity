using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.ViewModels
{
    /// <summary>
    /// 登录视图模型
    /// </summary>
    public class SignInViewModel
    {
        [Required(ErrorMessage = "请输入用户名、邮箱或电话号码")]
        [Display(Name = "用户名/邮箱/电话号码")]
        public string Account { get; set; } = string.Empty;

        [Required(ErrorMessage = "请输入密码")]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "记住我")]
        public bool RememberMe { get; set; }
    }
}
