using OpenFindBearings.Identity.Models.DTOs;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels
{
    /// <summary>
    /// 客户端视图模型 - 列表页
    /// </summary>
    public class ClientListViewModel
    {
        public PaginatedResult<ClientDto> Clients { get; set; } = null!;
        public string? SearchKeyword { get; set; }
    }

    /// <summary>
    /// 客户端视图模型
    /// </summary>
    public class ClientViewModel
    {
        [Display(Name = "客户端ID")]
        public string ClientId { get; set; } = string.Empty;

        [Display(Name = "显示名称")]
        public string DisplayName { get; set; } = string.Empty;

        [Display(Name = "客户端类型")]
        public string? ClientType { get; set; }

        [Display(Name = "允许的Scopes")]
        public IReadOnlyList<string> AllowedScopes { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// 创建客户端视图模型
    /// </summary>
    public class CreateClientViewModel
    {
        [Required(ErrorMessage = "客户端ID不能为空")]
        [Display(Name = "客户端ID")]
        public string ClientId { get; set; } = string.Empty;

        [Display(Name = "客户端密钥")]
        public string? ClientSecret { get; set; }

        [Required(ErrorMessage = "显示名称不能为空")]
        [Display(Name = "显示名称")]
        public string DisplayName { get; set; } = string.Empty;

        [Display(Name = "回调地址")]
        public string? RedirectUri { get; set; }

        [Display(Name = "登出回调地址")]
        public string? PostLogoutRedirectUri { get; set; }

        [Display(Name = "允许的Scopes")]
        public List<string> SelectedScopes { get; set; } = new();

        public List<ScopeSelection> AvailableScopes { get; set; } = new();
    }

    /// <summary>
    /// Scope 选择项
    /// </summary>
    public class ScopeSelection
    {
        public string Name { get; set; } = string.Empty;
        public bool Selected { get; set; }
    }
}