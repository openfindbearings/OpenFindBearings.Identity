using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 创建角色请求
    /// </summary>
    public class CreateRoleRequest
    {
        /// <summary>
        /// 角色名称（必填，2-50字符）
        /// </summary>
        [Required(ErrorMessage = "角色名称不能为空")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "角色名称长度必须在2-50字符之间")]
        public string Name { get; set; } = string.Empty;
    }
}
