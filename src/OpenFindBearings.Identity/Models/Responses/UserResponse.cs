namespace OpenFindBearings.Identity.Models.Responses
{
    /// <summary>
    /// 用户响应（API 返回）
    /// </summary>
    public class UserResponse
    {
        /// <summary>
        /// 用户ID
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// 用户名
        /// </summary>
        public string? UserName { get; set; }

        /// <summary>
        /// 邮箱
        /// </summary>
        public string? Email { get; set; }

        /// <summary>
        /// 邮箱是否已验证
        /// </summary>
        public bool EmailVerified { get; set; }

        /// <summary>
        /// 手机号
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// 手机号是否已验证
        /// </summary>
        public bool PhoneNumberVerified { get; set; }

        /// <summary>
        /// 全名
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// 名
        /// </summary>
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓
        /// </summary>
        public string? FamilyName { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; set; }

        /// <summary>
        /// 头像 URL
        /// </summary>
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站
        /// </summary>
        public string? WebsiteUrl { get; set; }

        /// <summary>
        /// 性别
        /// </summary>
        public string? Gender { get; set; }

        /// <summary>
        /// 出生日期
        /// </summary>
        public DateOnly? Birthdate { get; set; }

        /// <summary>
        /// 地区/语言
        /// </summary>
        public string? Locale { get; set; }

        /// <summary>
        /// 时区
        /// </summary>
        public string? ZoneInfo { get; set; }

        /// <summary>
        /// 地址
        /// </summary>
        public AddressResponse? Address { get; set; }

        /// <summary>
        /// 是否启用
        /// </summary>
        public bool IsEnabled { get; set; }

        /// <summary>
        /// 最后登录时间
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; }

        /// <summary>
        /// 更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; set; }

        /// <summary>
        /// 角色列表
        /// </summary>
        public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// 地址响应
    /// </summary>
    public class AddressResponse
    {
        /// <summary>
        /// 完整格式化的地址
        /// </summary>
        public string? Formatted { get; init; }

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
