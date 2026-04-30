using OpenFindBearings.Identity.Models.DTOs;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// Scope 视图模型 - 列表页
    /// </summary>
    public class ScopeListViewModel
    {
        public PaginatedResult<ScopeDto> Scopes { get; set; } = null!;
        public string? SearchKeyword { get; set; }
    }

    /// <summary>
    /// 创建 Scope 视图模型
    /// </summary>
    public class CreateScopeViewModel
    {
        [Required(ErrorMessage = "Scope名称不能为空")]
        [Display(Name = "Scope名称")]
        public string Name { get; set; } = string.Empty;

        [Display(Name = "显示名称")]
        public string? DisplayName { get; set; }

        [Display(Name = "描述")]
        public string? Description { get; set; }

        [Display(Name = "资源")]
        public string? Resources { get; set; }
    }
}