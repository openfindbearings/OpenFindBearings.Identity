using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 更新客户端请求
    /// </summary>
    public class UpdateClientRequest
    {
        /// <summary>显示名称（必填）</summary>
        [Required(ErrorMessage = "显示名称不能为空")]
        public string DisplayName { get; set; } = string.Empty;
    }
}
