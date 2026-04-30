using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Enums;
using OpenFindBearings.Identity.Models.ValueObjects;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// 用户视图模型 - 列表页
    /// </summary>
    public class UserListViewModel
    {
        public PaginatedResult<UserDto> Users { get; set; } = null!;
        public string? SearchKeyword { get; set; }
        public string? SortBy { get; set; }
        public bool SortDescending { get; set; }
        public UserStatusFilter? StatusFilter { get; set; }

        /// <summary>
        /// 用于表头显示
        /// </summary>
        public UserViewModel Display => new();
    }

    /// <summary>
    /// 用户视图模型 - 详情
    /// </summary>
    public class UserViewModel
    {
        public Guid Id { get; set; }
        public string Sub { get; set; } = string.Empty;

        [Display(Name = "用户名")]
        public string? UserName { get; set; }

        [Display(Name = "邮箱")]
        public string? Email { get; set; }

        [Display(Name = "邮箱已验证")]
        public bool EmailVerified { get; set; }

        [Display(Name = "手机号")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "手机已验证")]
        public bool PhoneNumberVerified { get; set; }

        [Display(Name = "全名")]
        public string? Name { get; set; }

        [Display(Name = "名")]
        public string? GivenName { get; set; }

        [Display(Name = "姓")]
        public string? FamilyName { get; set; }

        [Display(Name = "昵称")]
        public string? Nickname { get; set; }

        [Display(Name = "头像")]
        public string? PictureUrl { get; set; }

        [Display(Name = "个人网站")]
        public string? WebsiteUrl { get; set; }

        [Display(Name = "性别")]
        public string? Gender { get; set; }

        [Display(Name = "生日")]
        public DateOnly? Birthdate { get; set; }

        [Display(Name = "语言")]
        public string? Locale { get; set; }

        [Display(Name = "时区")]
        public string? ZoneInfo { get; set; }

        [Display(Name = "地址")]
        public Address? Address { get; set; }

        [Display(Name = "已启用")]
        public bool IsEnabled { get; set; }

        [Display(Name = "状态")]
        public bool IsActive { get; set; }

        [Display(Name = "最后登录")]
        public DateTimeOffset? LastLoginAt { get; set; }

        [Display(Name = "最后登录IP")]
        public string? LastLoginIp { get; set; }

        [Display(Name = "注册时间")]
        public DateTimeOffset CreatedAt { get; set; }

        [Display(Name = "更新时间")]
        public DateTimeOffset? UpdatedAt { get; set; }

        [Display(Name = "角色")]
        public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// 创建用户视图模型
    /// </summary>
    public class CreateUserViewModel
    {
        [Required(ErrorMessage = "用户名不能为空")]
        [Display(Name = "用户名")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "邮箱不能为空")]
        [EmailAddress(ErrorMessage = "邮箱格式不正确")]
        [Display(Name = "邮箱")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "密码不能为空")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "密码长度至少6位")]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "手机号")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "全名")]
        public string? Name { get; set; }

        [Display(Name = "名")]
        public string? GivenName { get; set; }

        [Display(Name = "姓")]
        public string? FamilyName { get; set; }

        [Display(Name = "昵称")]
        public string? Nickname { get; set; }

        [Display(Name = "已启用")]
        public bool IsEnabled { get; set; } = true;

        [Display(Name = "角色")]
        public List<string> SelectedRoles { get; set; } = new();

        public List<RoleSelection> AvailableRoles { get; set; } = new();
    }

    /// <summary>
    /// 编辑用户视图模型
    /// </summary>
    public class EditUserViewModel
    {
        public Guid Id { get; set; }

        [Display(Name = "用户名")]
        public string UserName { get; set; } = string.Empty;

        [EmailAddress(ErrorMessage = "邮箱格式不正确")]
        [Display(Name = "邮箱")]
        public string? Email { get; set; }

        [Display(Name = "手机号")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "全名")]
        public string? Name { get; set; }

        [Display(Name = "名")]
        public string? GivenName { get; set; }

        [Display(Name = "姓")]
        public string? FamilyName { get; set; }

        [Display(Name = "昵称")]
        public string? Nickname { get; set; }

        [Display(Name = "头像")]
        public string? PictureUrl { get; set; }

        [Display(Name = "个人网站")]
        public string? WebsiteUrl { get; set; }

        [Display(Name = "已启用")]
        public bool IsEnabled { get; set; }

        [Display(Name = "角色")]
        public List<string> SelectedRoles { get; set; } = new();

        public List<RoleSelection> AvailableRoles { get; set; } = new();
    }

    /// <summary>
    /// 角色选择项
    /// </summary>
    public class RoleSelection
    {
        public string Name { get; set; } = string.Empty;
        public bool Selected { get; set; }
    }
}