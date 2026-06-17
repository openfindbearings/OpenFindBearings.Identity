namespace OpenFindBearings.Identity.Models.ValueObjects
{
    /// <summary>
    /// 地址值对象 - OIDC 标准结构化地址
    /// 使用 record 确保不可变性
    /// </summary>
    public sealed record Address
    {
        /// <summary>
        /// 完整格式化的地址
        /// </summary>
        public string Formatted { get; init; } = string.Empty;
        
        /// <summary>
        /// 街道地址
        /// </summary>
        public string? StreetAddress { get; init; }
        
        /// <summary>
        /// 城市
        /// </summary>
        public string? Locality { get; init; }
        
        /// <summary>
        /// 省/州
        /// </summary>
        public string? Region { get; init; }
        
        /// <summary>
        /// 邮政编码
        /// </summary>
        public string? PostalCode { get; init; }
        
        /// <summary>
        /// 国家
        /// </summary>
        public string? Country { get; init; }
    }
}
