namespace OpenFindBearings.Identity.Areas.Admin.Models.ViewModels.User
{
    /// <summary>
    /// 用户视图模型 - 用于前端界面展示
    /// </summary>
    public class UserViewModel
    {
        public Guid Id { get; set; }
        public string Sub { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Name { get; set; }
        public bool EmailVerified { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public bool IsEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? LastLoginAt { get; set; }
        public string? LastLoginIp { get; set; }
        public string? LastLoginDevice { get; set; }
    }
}