using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 地址值对象 (address)
    /// OIDC 标准：符合规范的结构化地址对象
    /// 
    /// 为什么设计为独立类而不是嵌入 User 的字段？
    /// 1. 符合 OIDC 规范 - address 在规范中定义为一个 JSON 对象，而非扁平字段
    /// 2. 逻辑内聚 - 所有地址相关字段放在一起，便于理解和维护
    /// 3. 可复用性 - 其他实体（如企业、订单）也可能需要地址
    /// 4. 便于序列化 - 可以直接序列化为 JSON 返回给客户端
    /// 5. 扩展性 - 未来添加地址相关字段（如经纬度）只需修改此类
    /// 
    /// 使用 Fluent API 配置为 JSONB 列（PostgreSQL）
    /// </summary>
    public class Address
    {
        /// <summary>
        /// 完整格式化的地址
        /// 例如："中国北京市朝阳区建国门外大街1号 100020"
        /// </summary>
        [MaxLength(500)]
        public string? Formatted { get; set; }

        /// <summary>
        /// 街道地址
        /// 例如："建国门外大街1号"
        /// </summary>
        [MaxLength(200)]
        public string? StreetAddress { get; set; }

        /// <summary>
        /// 城市/ locality
        /// 例如："北京市"
        /// </summary>
        [MaxLength(100)]
        public string? Locality { get; set; }

        /// <summary>
        /// 省/州/ region
        /// 例如："北京市" 或 "California"
        /// </summary>
        [MaxLength(100)]
        public string? Region { get; set; }

        /// <summary>
        /// 邮政编码
        /// 例如："100020"
        /// </summary>
        [MaxLength(20)]
        public string? PostalCode { get; set; }

        /// <summary>
        /// 国家
        /// 例如："中国" 或 "United States"
        /// </summary>
        [MaxLength(100)]
        public string? Country { get; set; }
    }
}
