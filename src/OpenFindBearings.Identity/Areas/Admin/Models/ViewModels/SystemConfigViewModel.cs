using OpenFindBearings.Identity.Models.DTOs;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// 系统配置视图模型 - 列表页
    /// </summary>
    public class SystemConfigListViewModel
    {
        public PaginatedResult<SystemConfigDto> Configs { get; set; } = null!;
    }

    /// <summary>
    /// 编辑系统配置视图模型
    /// </summary>
    public class EditSystemConfigViewModel
    {
        [Required(ErrorMessage = "配置键不能为空")]
        [Display(Name = "配置键")]
        public string Key { get; set; } = string.Empty;

        [Required(ErrorMessage = "配置值不能为空")]
        [Display(Name = "配置值")]
        public string Value { get; set; } = string.Empty;

        [Display(Name = "描述")]
        public string? Description { get; set; }
    }
}
