namespace OpenFindBearings.Identity.Models.DTOs.Scope
{
    /// <summary>
    /// 更新 Scope 请求
    /// </summary>
    public class UpdateScopeDto
    {
        /// <summary>
        /// 显示名称
        /// </summary>
        public string? DisplayName { get; set; }

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// 受众/资源（audience）列表。null 表示不修改（保留既有）；非 null 表示整体替换。
        /// 改动说明：此前 Scope 编辑无法维护受众（token 的 aud 由各 scope 的 Resources 聚合），
        /// 现开放编辑，对齐 Keycloak 的 scope audience 概念。
        /// </summary>
        public IReadOnlyList<string>? Resources { get; set; }

        /// <summary>
        /// 受众输入框原始文本（每行一个），由控制器拆分后填充 Resources。仅视图绑定用。
        /// </summary>
        public string? ResourcesText { get; set; }
    }
}
