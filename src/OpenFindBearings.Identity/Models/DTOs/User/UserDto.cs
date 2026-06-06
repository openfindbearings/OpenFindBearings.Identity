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
        public DateTimeOffset? LastLoginAt { get; set; }
        public string? LastLoginIp { get; set; }
        public string? LastLoginDevice { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    }
}
