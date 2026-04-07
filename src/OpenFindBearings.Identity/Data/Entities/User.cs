using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 用户表 - 存储 OIDC 标准用户信息 + 业务扩展字段
    /// 支持登录方式：
    /// 1. 用户名/手机号/邮箱 + 密码
    /// 2. 手机号 + 短信验证码
    /// 3. 本机手机号一键登录（运营商网关）
    /// 4. 微信登录（小程序/Web扫码）
    /// 5. 支付宝登录
    /// 6. 刷新访问令牌
    /// 7. 客户端凭证（服务间调用）
    /// 
    /// 所有数据库映射使用 Fluent API 配置，无 Data Annotation
    /// </summary>
    public class User
    {
        // ==================== 1. OIDC 核心标识 ====================

        /// <summary>
        /// 用户唯一标识符 (sub - Subject)
        /// OIDC 标准：必需，在整个身份提供商范围内唯一且永久不变
        /// 格式：建议使用 UUID 或 雪花算法ID
        /// 对应 OpenIddict 中 Token.Subject 和 Authorization.Subject 字段
        /// </summary>
        public string Sub { get; set; } = string.Empty;

        /// <summary>
        /// 签发者标识 (iss - Issuer)
        /// OIDC 标准：可选，标识签发此用户信息的身份提供商 URL
        /// 例如："https://auth.yourdomain.com"
        /// </summary>
        public string? Issuer { get; set; }


        // ==================== 2. 本地认证凭证 ====================

        /// <summary>
        /// 用户名（唯一）
        /// 用于用户名+密码登录
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// 密码哈希值
        /// 使用 BCrypt 或 Argon2id 算法存储
        /// 用于密码登录方式
        /// </summary>
        public string? PasswordHash { get; set; }

        /// <summary>
        /// 电子邮箱（唯一）
        /// 用于邮箱+密码登录
        /// 请求 scope: email
        /// </summary>
        public string? Email { get; set; }

        /// <summary>
        /// 邮箱是否已验证
        /// true 表示邮箱确实属于该用户
        /// </summary>
        public bool EmailVerified { get; set; }

        /// <summary>
        /// 电话号码（E.164格式，唯一）
        /// 用于手机号+密码登录、手机号+短信验证码登录、本机号码一键登录
        /// 例如："+8613812345678"
        /// 请求 scope: phone
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// 手机号是否已验证
        /// true 表示手机号已完成短信验证
        /// </summary>
        public bool PhoneNumberVerified { get; set; }


        // ==================== 3. OIDC 用户资料 - 基本信息 ====================

        /// <summary>
        /// 用户的完整名称
        /// 例如 "张三" 或 "Alice Adams"
        /// 请求 scope: profile
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// 名（名字）
        /// 例如 "三" 或 "Alice"
        /// 请求 scope: profile
        /// </summary>
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓
        /// 例如 "张" 或 "Adams"
        /// 请求 scope: profile
        /// </summary>
        public string? FamilyName { get; set; }

        /// <summary>
        /// 中间名（常用于西方文化）
        /// 请求 scope: profile
        /// </summary>
        public string? MiddleName { get; set; }

        /// <summary>
        /// 昵称
        /// 例如 "Mike" 或 "小张"
        /// 请求 scope: profile
        /// </summary>
        public string? Nickname { get; set; }

        /// <summary>
        /// 偏好的用户名
        /// 用户希望在服务中显示的标识名
        /// 请求 scope: profile
        /// </summary>
        public string? PreferredUsername { get; set; }

        /// <summary>
        /// 个人资料页面 URL
        /// 指向用户个人主页的链接
        /// 请求 scope: profile
        /// </summary>
        public string? ProfileUrl { get; set; }

        /// <summary>
        /// 头像图片 URL
        /// 用户头像的图片地址
        /// 请求 scope: profile
        /// </summary>
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站 URL
        /// 用户的博客或个人网站
        /// 请求 scope: profile
        /// </summary>
        public string? WebsiteUrl { get; set; }

        /// <summary>
        /// 用户信息最后更新时间（Unix 时间戳）
        /// 表示用户信息最后修改时间
        /// 请求 scope: profile
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; set; }


        // ==================== 4. OIDC 用户资料 - 地址 ====================

        /// <summary>
        /// 地址信息
        /// OIDC 标准：可选，结构化的地址对象
        /// 使用 Fluent API 配置为 JSONB 列（PostgreSQL）
        /// 请求 scope: address
        /// </summary>
        public Address? Address { get; set; }


        // ==================== 5. OIDC 其他信息 ====================

        /// <summary>
        /// 性别
        /// 标准值: female, male，也支持自定义值
        /// 请求 scope: profile
        /// </summary>
        public string? Gender { get; set; }

        /// <summary>
        /// 生日（ISO 8601 格式: YYYY-MM-DD）
        /// 年份可以用 "0000" 表示不提供具体年份
        /// 请求 scope: profile
        /// </summary>
        public string? Birthdate { get; set; }

        /// <summary>
        /// 区域设置（BCP47 语言标签）
        /// 例如: zh-CN, en-US, zh-TW
        /// 请求 scope: profile
        /// </summary>
        public string? Locale { get; set; }

        /// <summary>
        /// 时区（IANA 时区数据库格式）
        /// 例如: Asia/Shanghai, America/New_York
        /// 请求 scope: profile
        /// </summary>
        public string? ZoneInfo { get; set; }


        // ==================== 6. 业务扩展字段 ====================

        /// <summary>
        /// 账户状态
        /// true: 正常，false: 禁用/锁定
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// 账户锁定到期时间
        /// 用于密码连续错误后的临时锁定
        /// </summary>
        public DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        /// 连续登录失败次数
        /// </summary>
        public int AccessFailedCount { get; set; }

        /// <summary>
        /// 注册时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 最后登录时间
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; set; }

        /// <summary>
        /// 最后登录IP
        /// </summary>
        [MaxLength(45)]
        public string? LastLoginIp { get; set; }

        /// <summary>
        /// 最后登录的设备类型
        /// </summary>
        [MaxLength(20)]
        public string? LastLoginDevice { get; set; }

        /// <summary>
        /// 自定义声明/扩展字段
        /// 用于存储标准之外的其他 OIDC 声明或业务数据
        /// 使用 Fluent API 配置为 JSONB 列
        /// </summary>
        public Dictionary<string, object>? CustomClaims { get; set; }


        // ==================== 7. 导航属性 ====================

        /// <summary>
        /// 第三方登录绑定列表
        /// </summary>
        public virtual ICollection<UserLoginBinding> LoginBindings { get; set; } = new List<UserLoginBinding>();

        /// <summary>
        /// 登录日志列表
        /// </summary>
        public virtual ICollection<UserLoginLog> LoginLogs { get; set; } = new List<UserLoginLog>();
    }
}
