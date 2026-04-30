using OpenFindBearings.Identity.Models.DTOs;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// 角色视图模型 - 列表页
    /// </summary>
    public class RoleListViewModel
    {
        public PaginatedResult<RoleViewModel> Roles { get; set; } = null!;
        public string? SearchKeyword { get; set; }

        /// <summary>
        /// 用于表头显示
        /// </summary>
        public RoleViewModel Display => new();
    }

    /// <summary>
    /// 角色视图模型
    /// </summary>
    public class RoleViewModel
    {
        public Guid Id { get; set; }

        [Display(Name = "角色名称")]
        public string Name { get; set; } = string.Empty;

        [Display(Name = "用户数量")]
        public int UserCount { get; set; }

        [Display(Name = "创建时间")]
        public DateTimeOffset CreatedAt { get; set; }
    }

    /// <summary>
    /// 创建角色视图模型
    /// </summary>
    public class CreateRoleViewModel
    {
        [Required(ErrorMessage = "角色名称不能为空")]
        [Display(Name = "角色名称")]
        public string Name { get; set; } = string.Empty;
    }
}
