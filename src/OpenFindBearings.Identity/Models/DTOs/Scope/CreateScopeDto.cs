using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.DTOs.Scope
{
    /// <summary>
    /// 创建 Scope 请求
    /// </summary>
    public class CreateScopeDto
    {
        /// <summary>
        /// Scope 名称（必填）
        /// </summary>
        [Required(ErrorMessage = "Scope 名称不能为空")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// 显示名称
        /// </summary>
        public string? DisplayName { get; set; }

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// 关联的资源列表
        /// </summary>
        public IReadOnlyList<string>? Resources { get; set; }
    }
}
