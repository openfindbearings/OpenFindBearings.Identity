using Microsoft.AspNetCore.Identity;
using OpenFindBearings.Identity.Models.ValueObjects;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// OIDC 用户实体 - 继承 IdentityUser，添加 OIDC 标准扩展字段
    /// </summary>
    public class OidcUser : IdentityUser<Guid>
    {
        // ========== OIDC 标准扩展字段 ==========

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
        /// 中间名
        /// </summary>
        public string? MiddleName { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; set; }

        /// <summary>
        /// 偏好的用户名
        /// </summary>
        public string? PreferredUsername { get; set; }

        /// <summary>
        /// 个人资料页 URL
        /// </summary>
        public string? ProfileUrl { get; set; }

        /// <summary>
        /// 头像 URL
        /// </summary>
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站 URL
        /// </summary>
        public string? WebsiteUrl { get; set; }

        /// <summary>
        /// 性别
        /// </summary>
        public string? Gender { get; set; }

        /// <summary>
        /// 生日
        /// </summary>
        public DateOnly? Birthdate { get; set; }

        /// <summary>
        /// 语言区域
        /// </summary>
        public string? Locale { get; set; }

        /// <summary>
        /// 时区
        /// </summary>
        public string? ZoneInfo { get; set; }

        /// <summary>
        /// 地址信息
        /// </summary>
        public Address? Address { get; set; }

        // ========== 业务审计字段 ==========

        /// <summary>
        /// 账户是否启用
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// 最后登录时间
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; set; }

        /// <summary>
        /// 最后登录 IP 地址
        /// </summary>
        public string? LastLoginIp { get; set; }

        /// <summary>
        /// 最后登录设备信息
        /// </summary>
        public string? LastLoginDevice { get; set; }

        /// <summary>
        /// 最后登录位置
        /// </summary>
        public string? LastLoginLocation { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 最后更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; set; }

        /// <summary>
        /// 是否激活（软删除）
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// 软删除时间
        /// </summary>
        public DateTimeOffset? DeletedAt { get; set; }

        // ========== 辅助属性 ==========

        /// <summary>
        /// OIDC Subject
        /// </summary>
        public string Sub => Id.ToString();

        /// <summary>
        /// 邮箱是否已验证
        /// </summary>
        public bool EmailVerified
        {
            get => EmailConfirmed;
            set => EmailConfirmed = value;
        }

        /// <summary>
        /// 手机是否已验证
        /// </summary>
        public bool PhoneNumberVerified
        {
            get => PhoneNumberConfirmed;
            set => PhoneNumberConfirmed = value;
        }

        // ========== 业务方法 ==========

        /// <summary>
        /// 软删除
        /// </summary>
        public void SoftDelete()
        {
            if (!IsActive) return;
            IsActive = false;
            DeletedAt = DateTimeOffset.UtcNow;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 恢复软删除
        /// </summary>
        public void Restore()
        {
            if (IsActive) return;
            IsActive = true;
            DeletedAt = null;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 启用账户
        /// </summary>
        public void Enable()
        {
            IsEnabled = true;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 禁用账户
        /// </summary>
        public void Disable()
        {
            IsEnabled = false;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 解锁账户
        /// </summary>
        public void Unlock()
        {
            LockoutEnd = null;
            AccessFailedCount = 0;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 重置登录失败计数
        /// </summary>
        public void ResetAccessFailedCount()
        {
            AccessFailedCount = 0;
            LockoutEnd = null;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 记录登录成功
        /// </summary>
        public void RecordSuccessfulLogin(string? ip = null, string? device = null, string? location = null)
        {
            LastLoginAt = DateTimeOffset.UtcNow;
            LastLoginIp = ip;
            LastLoginDevice = device;
            LastLoginLocation = location;
            AccessFailedCount = 0;
            LockoutEnd = null;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 记录登录失败
        /// </summary>
        public void RecordFailedLogin(int maxAttempts = 5, int lockoutMinutes = 15)
        {
            AccessFailedCount++;
            if (AccessFailedCount >= maxAttempts)
            {
                LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes);
            }
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 更新个人资料
        /// </summary>
        public void UpdateProfile(string? name, string? givenName, string? familyName,
            string? nickname = null, string? pictureUrl = null, string? websiteUrl = null)
        {
            Name = name ?? Name;
            GivenName = givenName ?? GivenName;
            FamilyName = familyName ?? FamilyName;
            Nickname = nickname ?? Nickname;
            PictureUrl = pictureUrl ?? PictureUrl;
            WebsiteUrl = websiteUrl ?? WebsiteUrl;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 更新地址
        /// </summary>
        public void UpdateAddress(Address? address)
        {
            Address = address;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 获取显示名称
        /// </summary>
        public string GetDisplayName()
        {
            return !string.IsNullOrEmpty(Name) ? Name
                 : !string.IsNullOrEmpty(Nickname) ? Nickname
                 : !string.IsNullOrEmpty(UserName) ? UserName
                 : !string.IsNullOrEmpty(Email) ? Email
                 : PhoneNumber ?? Id.ToString();
        }

        /// <summary>
        /// 检查是否可用
        /// </summary>
        public bool IsAvailable()
        {
            return IsActive && IsEnabled &&
                   (!LockoutEnabled || !LockoutEnd.HasValue || LockoutEnd < DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// 获取 OIDC 声明
        /// </summary>
        public Dictionary<string, object> GetOidcClaims()
        {
            var claims = new Dictionary<string, object> { ["sub"] = Sub };
            if (!string.IsNullOrEmpty(Name)) claims.Add("name", Name);
            if (!string.IsNullOrEmpty(GivenName)) claims.Add("given_name", GivenName);
            if (!string.IsNullOrEmpty(FamilyName)) claims.Add("family_name", FamilyName);
            if (!string.IsNullOrEmpty(Nickname)) claims.Add("nickname", Nickname);
            if (!string.IsNullOrEmpty(PreferredUsername)) claims.Add("preferred_username", PreferredUsername);
            if (!string.IsNullOrEmpty(ProfileUrl)) claims.Add("profile", ProfileUrl);
            if (!string.IsNullOrEmpty(PictureUrl)) claims.Add("picture", PictureUrl);
            if (!string.IsNullOrEmpty(WebsiteUrl)) claims.Add("website", WebsiteUrl);
            if (!string.IsNullOrEmpty(Gender)) claims.Add("gender", Gender);
            if (Birthdate.HasValue) claims.Add("birthdate", Birthdate.Value.ToString("yyyy-MM-dd"));
            if (!string.IsNullOrEmpty(Locale)) claims.Add("locale", Locale);
            if (!string.IsNullOrEmpty(ZoneInfo)) claims.Add("zoneinfo", ZoneInfo);
            if (!string.IsNullOrEmpty(Email)) claims.Add("email", Email);
            claims.Add("email_verified", EmailVerified);
            if (!string.IsNullOrEmpty(PhoneNumber)) claims.Add("phone_number", PhoneNumber);
            claims.Add("phone_number_verified", PhoneNumberVerified);
            return claims;
        }
    }
}
