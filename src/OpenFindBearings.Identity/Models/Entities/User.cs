using OpenFindBearings.Identity.Areas.Admin.Models.ViewModels.User;
using OpenIddict.Abstractions;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 用户领域模型 - 充血模型，包含业务逻辑
    /// 支持登录方式：用户名/邮箱/手机号+密码、手机号+短信验证码、微信登录、支付宝登录、刷新令牌、客户端凭证
    /// </summary>
    public sealed class User
    {
        /// <summary>
        /// 主键 (技术主键)
        /// </summary>
        public Guid Id { get; private set; }
        
        /// <summary>
        /// 用户唯一标识符 (sub - Subject)
        /// OIDC 标准：必需，在整个身份提供商范围内唯一且永久不变
        /// </summary>
        public string Sub { get; private set; }
        
        /// <summary>
        /// 用户名（唯一）
        /// </summary>
        public string? Username { get; private set; }
        
        /// <summary>
        /// 电子邮箱（唯一）
        /// </summary>
        public string? Email { get; private set; }
        
        /// <summary>
        /// 电话号码（E.164格式，唯一）
        /// </summary>
        public string? PhoneNumber { get; private set; }
        
        /// <summary>
        /// 密码哈希值
        /// </summary>
        public string? PasswordHash { get; private set; }
        
        /// <summary>
        /// 邮箱是否已验证
        /// </summary>
        public bool EmailVerified { get; private set; }
        
        /// <summary>
        /// 手机号是否已验证
        /// </summary>
        public bool PhoneNumberVerified { get; private set; }
        
        /// <summary>
        /// 用户的完整名称
        /// </summary>
        public string? Name { get; private set; }
        
        /// <summary>
        /// 名
        /// </summary>
        public string? GivenName { get; private set; }
        
        /// <summary>
        /// 姓
        /// </summary>
        public string? FamilyName { get; private set; }
        
        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; private set; }
        
        /// <summary>
        /// 偏好的用户名
        /// </summary>
        public string? PreferredUsername { get; private set; }
        
        /// <summary>
        /// 个人资料页面 URL
        /// </summary>
        public string? ProfileUrl { get; private set; }
        
        /// <summary>
        /// 头像图片 URL
        /// </summary>
        public string? PictureUrl { get; private set; }
        
        /// <summary>
        /// 个人网站 URL
        /// </summary>
        public string? WebsiteUrl { get; private set; }
        
        /// <summary>
        /// 性别
        /// </summary>
        public string? Gender { get; private set; }
        
        /// <summary>
        /// 生日（ISO 8601 格式: YYYY-MM-DD）
        /// </summary>
        public string? Birthdate { get; private set; }
        
        /// <summary>
        /// 区域设置（BCP47 语言标签）
        /// </summary>
        public string? Locale { get; private set; }
        
        /// <summary>
        /// 时区（IANA 时区数据库格式）
        /// </summary>
        public string? ZoneInfo { get; private set; }
        
        /// <summary>
        /// 签发者标识 (iss - Issuer)
        /// </summary>
        public string? Issuer { get; private set; }
        
        /// <summary>
        /// 用户信息最后更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; private set; }
        
        /// <summary>
        /// 地址信息
        /// </summary>
        public Address? Address { get; private set; }
        
        /// <summary>
        /// 账户是否启用
        /// true: 正常，false: 禁用
        /// </summary>
        public bool IsEnabled { get; private set; } = true;
        
        /// <summary>
        /// 软删除标记
        /// true: 正常，false: 已删除
        /// </summary>
        public bool IsActive { get; private set; } = true;
        
        /// <summary>
        /// 账户锁定到期时间
        /// </summary>
        public DateTimeOffset? LockoutEnd { get; private set; }
        
        /// <summary>
        /// 连续登录失败次数
        /// </summary>
        public int AccessFailedCount { get; private set; }
        
        /// <summary>
        /// 注册时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }
        
        /// <summary>
        /// 最后登录时间
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; private set; }
        
        /// <summary>
        /// 最后登录IP
        /// </summary>
        public string? LastLoginIp { get; private set; }
        
        /// <summary>
        /// 最后登录的设备类型
        /// </summary>
        public string? LastLoginDevice { get; private set; }
        
        /// <summary>
        /// 删除时间（软删除）
        /// </summary>
        public DateTimeOffset? DeletedAt { get; private set; }
        
        /// <summary>
        /// 自定义声明/扩展字段
        /// </summary>
        public Dictionary<string, object>? CustomClaims { get; private set; }

        /// <summary>
        /// 无参构造函数 - 仅供 EF Core 使用
        /// </summary>
        private User() { }

        /// <summary>
        /// 创建新用户
        /// </summary>
        public static User Create(string sub, string? username = null, string? email = null, string? phoneNumber = null)
        {
            if (string.IsNullOrWhiteSpace(sub))
                throw new ArgumentException("Sub cannot be empty", nameof(sub));

            return new User
            {
                Id = Guid.NewGuid(),
                Sub = sub,
                Username = username,
                Email = email,
                PhoneNumber = phoneNumber,
                IsEnabled = true,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        internal static User Create(Guid id, string sub, string? username, string? email, string? phoneNumber, string? passwordHash,
            bool emailVerified, bool phoneNumberVerified, string? name, string? givenName, string? familyName, string? nickname,
            string? preferredUsername, bool isEnabled, DateTimeOffset createdAt, DateTimeOffset? lastLoginAt, string? lastLoginIp,
            string? lastLoginDevice, Dictionary<string, object>? customClaims, Address? address, string? gender, string? birthdate,
            string? locale, string? zoneInfo, int accessFailedCount = 0, DateTimeOffset? lockoutEnd = null)
        {
            return new User
            {
                Id = id,
                Sub = sub,
                Username = username,
                Email = email,
                PhoneNumber = phoneNumber,
                PasswordHash = passwordHash,
                EmailVerified = emailVerified,
                PhoneNumberVerified = phoneNumberVerified,
                Name = name,
                GivenName = givenName,
                FamilyName = familyName,
                Nickname = nickname,
                PreferredUsername = preferredUsername,
                Gender = gender,
                Birthdate = birthdate,
                Locale = locale,
                ZoneInfo = zoneInfo,
                IsEnabled = isEnabled,
                IsActive = true,
                CreatedAt = createdAt,
                LastLoginAt = lastLoginAt,
                LastLoginIp = lastLoginIp,
                LastLoginDevice = lastLoginDevice,
                CustomClaims = customClaims,
                Address = address,
                AccessFailedCount = accessFailedCount,
                LockoutEnd = lockoutEnd
            };
        }

        /// <summary>
        /// 验证密码是否匹配
        /// </summary>
        public bool CheckPassword(string password, Func<string, string, bool> validator)
        {
            return !string.IsNullOrEmpty(PasswordHash) && validator(password, PasswordHash);
        }

        /// <summary>
        /// 更新密码
        /// </summary>
        public void UpdatePassword(string passwordHash)
        {
            PasswordHash = passwordHash;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 验证用户是否可以登录
        /// </summary>
        public (bool CanLogin, string? Reason) ValidateForLogin()
        {
            if (!IsEnabled)
                return (false, "账户已被禁用");
            
            if (LockoutEnd.HasValue && LockoutEnd > DateTimeOffset.UtcNow)
                return (false, $"账户已被锁定至 {LockoutEnd.Value:g}");

            return (true, null);
        }

        /// <summary>
        /// 记录登录成功
        /// </summary>
        public void RecordLoginSuccess(string? ip = null, string? device = null)
        {
            LastLoginAt = DateTimeOffset.UtcNow;
            LastLoginIp = ip;
            LastLoginDevice = device;
            AccessFailedCount = 0;
        }

        /// <summary>
        /// 记录登录失败
        /// </summary>
        public void RecordLoginFailure(int maxFailedAttempts = 5, int lockoutMinutes = 30)
        {
            AccessFailedCount++;
            if (AccessFailedCount >= maxFailedAttempts)
            {
                LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes);
            }
        }

        /// <summary>
        /// 启用账户
        /// </summary>
        public void Enable()
        {
            IsEnabled = true;
            LockoutEnd = null;
            AccessFailedCount = 0;
        }

        /// <summary>
        /// 禁用账户
        /// </summary>
        public void Disable()
        {
            IsEnabled = false;
        }

        /// <summary>
        /// 软删除
        /// </summary>
        public void SoftDelete()
        {
            IsActive = false;
            DeletedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 恢复软删除
        /// </summary>
        public void Restore()
        {
            IsActive = true;
            DeletedAt = null;
        }

        /// <summary>
        /// 获取显示名称
        /// </summary>
        public string GetDisplayName()
        {
            return !string.IsNullOrEmpty(Name) ? Name
                 : !string.IsNullOrEmpty(Nickname) ? Nickname
                 : !string.IsNullOrEmpty(Username) ? Username
                 : !string.IsNullOrEmpty(Email) ? Email
                 : PhoneNumber ?? Sub;
        }

        /// <summary>
        /// 更新个人资料
        /// </summary>
        public void UpdateProfile(string? name = null, string? givenName = null, string? familyName = null, string? nickname = null)
        {
            Name = name ?? Name;
            GivenName = givenName ?? GivenName;
            FamilyName = familyName ?? FamilyName;
            Nickname = nickname ?? Nickname;
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
        /// 转换为视图模型
        /// </summary>
        public UserViewModel ToViewModel()
        {
            return new UserViewModel
            {
                Id = Id,
                Sub = Sub,
                Username = Username,
                Email = Email,
                PhoneNumber = PhoneNumber,
                Name = Name,
                EmailVerified = EmailVerified,
                PhoneNumberVerified = PhoneNumberVerified,
                IsEnabled = IsEnabled,
                LockoutEnd = LockoutEnd,
                AccessFailedCount = AccessFailedCount,
                CreatedAt = CreatedAt,
                LastLoginAt = LastLoginAt,
                LastLoginIp = LastLoginIp,
                LastLoginDevice = LastLoginDevice
            };
        }

        /// <summary>
        /// 配置用户权限
        /// </summary
        public void SetRoles(string[] roles)
        {
            CustomClaims!["roles"] = roles;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 清空用户权限
        /// </summary>
        public void ClearRoles()
        {
            CustomClaims!["roles"] = Array.Empty<string>();
            UpdatedAt = DateTimeOffset.UtcNow;
        }
    }
}
