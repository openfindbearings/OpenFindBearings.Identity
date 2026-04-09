namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 用户数据传输对象 - 用于层间数据传输
    /// </summary>
    public class UserDto
    {
        public Guid Id { get; set; }
        public string Sub { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Name { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
        public string? Nickname { get; set; }
        public string? PictureUrl { get; set; }
        public bool EmailVerified { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public bool IsEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? LastLoginAt { get; set; }
        public string? LastLoginIp { get; set; }
        public string? LastLoginDevice { get; set; }
        public AddressDto? Address { get; set; }
    }

    /// <summary>
    /// 地址数据传输对象
    /// </summary>
    public class AddressDto
    {
        public string? Formatted { get; set; }
        public string? StreetAddress { get; set; }
        public string? Locality { get; set; }
        public string? Region { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }
    }
}