using OpenFindBearings.Identity.Models.ValueObjects;

namespace OpenFindBearings.Identity.Models.DTOs.User
{
    /// <summary>
    /// 用户数据传输对象
    /// </summary>
    public class UserDto
    {
        public Guid Id { get; set; }
        public string Sub { get; set; } = string.Empty;
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public bool EmailVerified { get; set; }
        public string? PhoneNumber { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public string? Name { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
        public string? Nickname { get; set; }
        public string? PictureUrl { get; set; }
        public string? WebsiteUrl { get; set; }
        public string? Gender { get; set; }
        public DateOnly? Birthdate { get; set; }
        public string? Locale { get; set; }
        public string? ZoneInfo { get; set; }
        public Address? Address { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsActive { get; set; }
    // 改动说明（v2.19.1）：临时锁定态（5 次输错密码锁 15 分钟）透出给 Admin 列表，
    // 支撑"已锁定"筛选视图的徽章显示与解锁按钮
    public bool IsLockedOut { get; set; }
        public DateTimeOffset? LastLoginAt { get; set; }
        public string? LastLoginIp { get; set; }
        public string? LastLoginDevice { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? TenantId { get; set; }
        public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    }
}
