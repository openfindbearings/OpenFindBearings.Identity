using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Net;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 用户表 - 存储 OIDC 标准用户信息 + 业务扩展字段
    /// 对应 OpenIddict 中的 Subject（用户唯一标识）
    /// </summary>
    [Table("Users")]
    public class User
    {
        // ==================== 1. OIDC 核心标识 ====================

        /// <summary>
        /// 用户唯一标识符 (sub - Subject)
        /// OIDC 标准：必需，在整个身份提供商范围内唯一且永久不变
        /// 对应 OpenIddict 中 Token.Subject 和 Authorization.Subject 字段
        /// </summary>
        [Key]
        [MaxLength(255)]
        [Required]
        public string Sub { get; set; } = string.Empty;

        /// <summary>
        /// 签发者标识 (iss - Issuer)
        /// OIDC 标准：可选，标识签发此用户信息的身份提供商 URL
        /// 例如："https://auth.yourdomain.com"
        /// </summary>
        [MaxLength(500)]
        public string? Issuer { get; set; }

        // ==================== 2. OIDC 用户资料 - 基本信息 ====================

        /// <summary>
        /// 用户的完整名称 (name)
        /// OIDC 标准：可选，例如 "张三" 或 "Alice Adams"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(255)]
        public string? Name { get; set; }

        /// <summary>
        /// 名 (given_name)
        /// OIDC 标准：可选，例如 "三" 或 "Alice"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(100)]
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓 (family_name)
        /// OIDC 标准：可选，例如 "张" 或 "Adams"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(100)]
        public string? FamilyName { get; set; }

        /// <summary>
        /// 中间名 (middle_name)
        /// OIDC 标准：可选，常用于西方文化，例如 "Marie"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(100)]
        public string? MiddleName { get; set; }

        /// <summary>
        /// 昵称 (nickname)
        /// OIDC 标准：可选，例如 "Mike" 或 "小张"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(100)]
        public string? Nickname { get; set; }

        /// <summary>
        /// 偏好的用户名 (preferred_username)
        /// OIDC 标准：可选，用户希望在服务中显示的标识名
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(100)]
        public string? PreferredUsername { get; set; }

        /// <summary>
        /// 个人资料页面 URL (profile)
        /// OIDC 标准：可选，指向用户个人主页的链接
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(500)]
        public string? ProfileUrl { get; set; }

        /// <summary>
        /// 头像图片 URL (picture)
        /// OIDC 标准：可选，用户头像的图片地址
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(500)]
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站 URL (website)
        /// OIDC 标准：可选，用户的博客或个人网站
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(500)]
        public string? WebsiteUrl { get; set; }

        /// <summary>
        /// 用户信息最后更新时间 (updated_at)
        /// OIDC 标准：可选，Unix 时间戳，表示用户信息最后修改时间
        /// 请求 scope: profile
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; set; }

        // ==================== 3. OIDC 用户资料 - 联系方式 ====================

        /// <summary>
        /// 电子邮箱 (email)
        /// OIDC 标准：可选，用户的邮箱地址
        /// 请求 scope: email
        /// </summary>
        [MaxLength(255)]
        [EmailAddress]
        public string? Email { get; set; }

        /// <summary>
        /// 邮箱是否已验证 (email_verified)
        /// OIDC 标准：可选，true 表示邮箱确实属于该用户
        /// 请求 scope: email
        /// </summary>
        public bool EmailVerified { get; set; }

        /// <summary>
        /// 电话号码 (phone_number)
        /// OIDC 标准：可选，建议使用 E.164 格式，如 "+8613812345678"
        /// 请求 scope: phone
        /// </summary>
        [MaxLength(32)]
        [Phone]
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// 手机号是否已验证 (phone_number_verified)
        /// OIDC 标准：可选，true 表示手机号已验证
        /// 请求 scope: phone
        /// </summary>
        public bool PhoneNumberVerified { get; set; }

        // ==================== 4. OIDC 用户资料 - 地址 ====================

        /// <summary>
        /// 地址信息 (address)
        /// OIDC 标准：可选，结构化的地址对象
        /// 请求 scope: address
        /// 
        /// 重要说明：Address 是一个独立的类（Owned Type），
        /// 在 EF Core 中会被映射到 User 表的多个列（如 Address_Formatted, Address_Locality 等），
        /// 或者如果配置为 JSON 列，则存储为 JSON 格式。
        /// 
        /// 为什么要设计成独立类？
        /// 1. 地址是一个逻辑整体，包含多个子字段（街道、城市、邮编等）
        /// 2. 符合 OIDC 规范中 address 声明的 JSON 结构
        /// 3. 便于复用（其他地方也可能需要地址）
        /// 4. 便于未来扩展（如添加经纬度等字段）
        /// </summary>
        public Address? Address { get; set; }

        // ==================== 5. OIDC 其他信息 ====================

        /// <summary>
        /// 性别 (gender)
        /// OIDC 标准：可选，标准值定义为 "female" 和 "male"，也支持自定义值
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(20)]
        public string? Gender { get; set; }

        /// <summary>
        /// 生日 (birthdate)
        /// OIDC 标准：可选，ISO 8601 格式 (YYYY-MM-DD)
        /// 年份可以用 "0000" 表示不提供具体年份，如 "0000-03-15"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(10)]
        public string? Birthdate { get; set; }

        /// <summary>
        /// 区域设置 (locale)
        /// OIDC 标准：可选，BCP47 语言标签格式
        /// 例如："zh-CN"（简体中文）、"en-US"（美式英语）、"zh-TW"（繁体中文）
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(20)]
        public string? Locale { get; set; }

        /// <summary>
        /// 时区 (zoneinfo)
        /// OIDC 标准：可选，IANA 时区数据库格式
        /// 例如："Asia/Shanghai"、"America/New_York"、"Europe/London"
        /// 请求 scope: profile
        /// </summary>
        [MaxLength(50)]
        public string? ZoneInfo { get; set; }

        // ==================== 6. 业务扩展字段（非 OIDC 标准） ====================

        /// <summary>
        /// 密码哈希值（用于密码模式认证）
        /// 使用 PBKDF2、bcrypt 或 Argon2 等安全算法存储
        /// </summary>
        [MaxLength(500)]
        public string? PasswordHash { get; set; }

        /// <summary>
        /// 创建时间（本地扩展）
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 最后登录时间（本地扩展）
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; set; }

        /// <summary>
        /// 账号是否启用（本地扩展）
        /// false 表示账号被锁定或禁用
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// 自定义声明/扩展字段
        /// 用于存储标准之外的其他 OIDC 声明或业务数据
        /// 在 PostgreSQL 中使用 JSONB 类型，性能更好
        /// </summary>
        [Column(TypeName = "jsonb")]
        public Dictionary<string, object>? CustomClaims { get; set; }
    }
}
