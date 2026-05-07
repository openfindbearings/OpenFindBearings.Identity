using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 创建客户端请求
    /// </summary>
    public class CreateClientRequest
    {
        /// <summary>客户端ID（必填）</summary>
        [Required(ErrorMessage = "ClientId 不能为空")]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>客户端密钥（机密客户端必填）</summary>
        public string? ClientSecret { get; set; }

        /// <summary>显示名称（必填）</summary>
        [Required(ErrorMessage = "显示名称不能为空")]
        public string DisplayName { get; set; } = string.Empty;

        /// <summary>回调地址</summary>
        [Url(ErrorMessage = "回调地址格式不正确")]
        public string? RedirectUri { get; set; }

        /// <summary>允许的作用域列表</summary>
        public List<string>? Scopes { get; set; }
    }
}
