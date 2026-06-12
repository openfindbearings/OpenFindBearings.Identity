using Microsoft.AspNetCore.Identity;
using OpenFindBearings.Identity.Models.ValueObjects;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// OIDC 用户实体 - 继承 IdentityUser，添加 OIDC 标准扩展字段
    /// 采用充血模型设计，业务逻辑内聚在实体中
    /// </summary>
    public class OidcUser : IdentityUser<Guid>
    {
        // ========== 构造函数 ==========

        /// <summary>
        /// 无参构造函数 - EF Core 需要（private 确保外部不能直接 new）
        /// </summary>
        private OidcUser() { }

        /// <summary>
        /// 工厂方法 - 创建新用户（唯一创建方式）
        /// </summary>
        /// <param name="userName">用户名</param>
        /// <param name="email">邮箱</param>
        /// <param name="tenantId">租户标识</param>
        /// <param name="phoneNumber">手机号（可选）</param>
        /// <param name="name">全名（可选）</param>
        /// <param name="givenName">名（可选）</param>
        /// <param name="familyName">姓（可选）</param>
        /// <returns>新创建的用户实体</returns>
        public static OidcUser Create(
            string userName,
            string? email,
            Guid tenantId,
            string? phoneNumber = null,
            string? name = null,
            string? givenName = null,
            string? familyName = null)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentException("用户名不能为空", nameof(userName));

            //if (string.IsNullOrWhiteSpace(email))
            //    throw new ArgumentException("邮箱不能为空", nameof(email));

            return new OidcUser
            {
                UserName = userName,
                Email = email,
                TenantId = tenantId,
                PhoneNumber = phoneNumber,
                Name = name,
                GivenName = givenName,
                FamilyName = familyName,
                IsEnabled = true,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                // Identity 默认值
                LockoutEnabled = true,  // 启用锁定功能
                EmailConfirmed = false,  // 邮箱未验证
                PhoneNumberConfirmed = false,  // 手机未验证
                TwoFactorEnabled = false  // 未启用双因素
            };
        }

        // ========== OIDC 标准扩展字段 ==========

        /// <summary>
        /// 全名
        /// </summary>
        public string? Name { get; private set; }

        /// <summary>
        /// 名（Given Name）
        /// </summary>
        public string? GivenName { get; private set; }

        /// <summary>
        /// 姓（Family Name）
        /// </summary>
        public string? FamilyName { get; private set; }

        /// <summary>
        /// 中间名
        /// </summary>
        public string? MiddleName { get; private set; }

        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; private set; }

        /// <summary>
        /// 偏好的用户名（用于显示）
        /// </summary>
        public string? PreferredUsername { get; private set; }

        /// <summary>
        /// 个人资料页 URL
        /// </summary>
        public string? ProfileUrl { get; private set; }

        /// <summary>
        /// 头像 URL
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
        /// 生日
        /// </summary>
        public DateOnly? Birthdate { get; private set; }

        /// <summary>
        /// 语言区域（如 zh-CN、en-US）
        /// </summary>
        public string? Locale { get; private set; }

        /// <summary>
        /// 时区（IANA 格式，如 Asia/Shanghai）
        /// </summary>
        public string? ZoneInfo { get; private set; }

        /// <summary>
        /// 地址信息（值对象）
        /// </summary>
        public Address? Address { get; private set; }

        // ========== 业务审计字段 ==========

        /// <summary>
        /// 租户标识
        /// 每个用户必须归属一个租户，用于多租户隔离
        /// </summary>
        public Guid TenantId { get; set; }

        /// <summary>
        /// 账户是否启用（业务禁用，由管理员控制）
        /// 与 Identity 的 LockoutEnabled 不同：
        /// - IsEnabled: 管理员永久禁用/启用
        /// - LockoutEnabled: 系统临时锁定（输错密码）
        /// </summary>
        public bool IsEnabled { get; private set; } = true;

        /// <summary>
        /// 最后登录时间
        /// </summary>
        public DateTimeOffset? LastLoginAt { get; private set; }

        /// <summary>
        /// 最后登录 IP 地址
        /// </summary>
        public string? LastLoginIp { get; private set; }

        /// <summary>
        /// 最后登录设备信息（UserAgent 解析结果）
        /// </summary>
        public string? LastLoginDevice { get; private set; }

        /// <summary>
        /// 最后登录位置（IP 解析结果）
        /// </summary>
        public string? LastLoginLocation { get; private set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 最后更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; private set; }

        /// <summary>
        /// 是否激活（软删除标记）
        /// </summary>
        public bool IsActive { get; private set; } = true;

        /// <summary>
        /// 软删除时间
        /// </summary>
        public DateTimeOffset? DeletedAt { get; private set; }

        // ========== 辅助属性 ==========

        /// <summary>
        /// OIDC Subject - 唯一标识符
        /// </summary>
        public string Sub => Id.ToString();

        /// <summary>
        /// 邮箱是否已验证（映射到 Identity 的 EmailConfirmed）
        /// </summary>
        public bool EmailVerified
        {
            get => EmailConfirmed;
            private set => EmailConfirmed = value;
        }

        /// <summary>
        /// 手机是否已验证（映射到 Identity 的 PhoneNumberConfirmed）
        /// </summary>
        public bool PhoneNumberVerified
        {
            get => PhoneNumberConfirmed;
            private set => PhoneNumberConfirmed = value;
        }

        // ========== 状态管理方法 ==========

        /// <summary>
        /// 启用账户（管理员操作）
        /// 同时清除系统锁定状态，让账户立即可用
        /// </summary>
        public void Enable()
        {
            if (IsEnabled) return;

            IsEnabled = true;
            LockoutEnd = null;      // 清除锁定
            AccessFailedCount = 0;  // 清除失败计数
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 禁用账户（管理员操作）
        /// 与软删除的区别：禁用是临时性的，软删除是永久性的数据隔离
        /// </summary>
        public void Disable()
        {
            if (!IsEnabled) return;

            IsEnabled = false;
            LockoutEnabled = true;
            LockoutEnd = DateTimeOffset.MaxValue;  // 永不过期的锁定
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 软删除（数据隔离，可恢复）
        /// 禁用账户 + 标记删除，用户数据保留但不显示
        /// </summary>
        public void SoftDelete()
        {
            if (!IsActive) return;

            IsActive = false;
            IsEnabled = false;
            DeletedAt = DateTimeOffset.UtcNow;
            LockoutEnabled = true;
            LockoutEnd = DateTimeOffset.MaxValue;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 恢复软删除
        /// 注意：恢复后账户仍为禁用状态，需要管理员手动启用
        /// </summary>
        public void Restore()
        {
            if (IsActive) return;

            IsActive = true;
            DeletedAt = null;
            // 注意：不自动启用账户，由管理员决定是否启用
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 手动解锁账户（管理员操作）
        /// 清除系统临时锁定，不改变 IsEnabled 状态
        /// </summary>
        public void Unlock()
        {
            LockoutEnd = null;
            AccessFailedCount = 0;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        // ========== 登录相关方法 ==========

        /// <summary>
        /// 记录登录成功
        /// 更新审计字段，重置失败计数和锁定状态
        /// </summary>
        /// <param name="ip">登录 IP</param>
        /// <param name="device">设备信息</param>
        /// <param name="location">地理位置</param>
        public void RecordSuccessfulLogin(string? ip = null, string? device = null, string? location = null)
        {
            LastLoginAt = DateTimeOffset.UtcNow;
            LastLoginIp = ip;
            LastLoginDevice = device;
            LastLoginLocation = location;

            // 重置 Identity 的失败计数和锁定
            AccessFailedCount = 0;
            LockoutEnd = null;

            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 记录登录失败
        /// 增加失败计数，达到阈值时触发锁定
        /// 注意：详细的失败审计（IP、设备等）由 AuditLog 负责记录
        /// </summary>
        /// <param name="maxAttempts">最大失败次数（默认5次）</param>
        /// <param name="lockoutMinutes">锁定时间（分钟，默认15分钟）</param>
        /// <returns>是否触发了锁定</returns>
        public bool RecordFailedLogin(int maxAttempts = 5, int lockoutMinutes = 15)
        {
            AccessFailedCount++;
            UpdatedAt = DateTimeOffset.UtcNow;

            // 检查是否需要锁定
            if (AccessFailedCount >= maxAttempts && LockoutEnabled)
            {
                LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes);
                return true;  // 已锁定
            }

            return false;  // 未锁定
        }

        // ========== 资料管理方法 ==========

        /// <summary>
        /// 更新个人资料
        /// </summary>
        /// <param name="name">全名</param>
        /// <param name="givenName">名</param>
        /// <param name="familyName">姓</param>
        /// <param name="nickname">昵称</param>
        /// <param name="pictureUrl">头像 URL</param>
        /// <param name="websiteUrl">个人网站</param>
        public void UpdateProfile(
            string? name = null,
            string? givenName = null,
            string? familyName = null,
            string? nickname = null,
            string? pictureUrl = null,
            string? websiteUrl = null,
            string? gender = null,
            DateOnly? birthdate = null,
            string? locale = null,
            string? zoneInfo = null,
            Address? address = null)
        {
            Name = name ?? Name;
            GivenName = givenName ?? GivenName;
            FamilyName = familyName ?? FamilyName;
            Nickname = nickname ?? Nickname;
            PictureUrl = pictureUrl ?? PictureUrl;
            WebsiteUrl = websiteUrl ?? WebsiteUrl;

            Gender = gender ?? Gender;
            Birthdate = birthdate ?? Birthdate;
            Locale = locale ?? Locale;
            ZoneInfo = zoneInfo ?? ZoneInfo;

            if (address != null)
                Address = address;

            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置中间名
        /// </summary>
        public void SetMiddleName(string? middleName)
        {
            MiddleName = middleName;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置偏好用户名
        /// </summary>
        public void SetPreferredUsername(string? preferredUsername)
        {
            PreferredUsername = preferredUsername;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置个人资料页 URL
        /// </summary>
        public void SetProfileUrl(string? profileUrl)
        {
            ProfileUrl = profileUrl;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置性别
        /// </summary>
        public void SetGender(string? gender)
        {
            Gender = gender;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置生日
        /// </summary>
        public void SetBirthdate(DateOnly? birthdate)
        {
            Birthdate = birthdate;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置语言区域
        /// </summary>
        public void SetLocale(string? locale)
        {
            Locale = locale;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 设置时区
        /// </summary>
        public void SetZoneInfo(string? zoneInfo)
        {
            ZoneInfo = zoneInfo;
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
        /// 确认邮箱
        /// </summary>
        public void ConfirmEmail()
        {
            EmailConfirmed = true;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 确认手机
        /// </summary>
        public void ConfirmPhoneNumber()
        {
            PhoneNumberConfirmed = true;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        // ========== 查询方法 ==========

        /// <summary>
        /// 获取显示名称（优先级：全名 > 昵称 > 用户名 > 邮箱 > 手机号 > ID）
        /// </summary>
        public string GetDisplayName()
        {
            return Name ?? Nickname ?? UserName ?? Email ?? PhoneNumber ?? Id.ToString();
        }

        /// <summary>
        /// 检查账户是否可用（综合所有状态）
        /// </summary>
        public bool IsAvailable()
        {
            // 软删除检查
            if (!IsActive) return false;

            // 业务禁用检查
            if (!IsEnabled) return false;

            // Identity 临时锁定检查（输错密码锁定）
            if (LockoutEnabled && LockoutEnd.HasValue && LockoutEnd > DateTimeOffset.UtcNow)
                return false;

            return true;
        }

        /// <summary>
        /// 检查账户是否被临时锁定（输错密码导致）
        /// </summary>
        public bool IsTemporarilyLocked()
        {
            return LockoutEnabled && LockoutEnd.HasValue && LockoutEnd > DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 获取剩余锁定时间（如果是临时锁定状态）
        /// </summary>
        public TimeSpan? GetRemainingLockoutTime()
        {
            if (!IsTemporarilyLocked() || !LockoutEnd.HasValue)
                return null;

            var remaining = LockoutEnd.Value - DateTimeOffset.UtcNow;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        // ========== OIDC Claim 方法 ==========

        /// <summary>
        /// 获取 OIDC 声明（用于生成 ID Token 和 UserInfo）
        /// </summary>
        public Dictionary<string, object> GetOidcClaims()
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = Sub
            };

            // 标准 Claims
            if (!string.IsNullOrEmpty(Name)) claims.Add("name", Name);
            if (!string.IsNullOrEmpty(GivenName)) claims.Add("given_name", GivenName);
            if (!string.IsNullOrEmpty(FamilyName)) claims.Add("family_name", FamilyName);
            if (!string.IsNullOrEmpty(MiddleName)) claims.Add("middle_name", MiddleName);
            if (!string.IsNullOrEmpty(Nickname)) claims.Add("nickname", Nickname);
            if (!string.IsNullOrEmpty(PreferredUsername)) claims.Add("preferred_username", PreferredUsername);
            if (!string.IsNullOrEmpty(ProfileUrl)) claims.Add("profile", ProfileUrl);
            if (!string.IsNullOrEmpty(PictureUrl)) claims.Add("picture", PictureUrl);
            if (!string.IsNullOrEmpty(WebsiteUrl)) claims.Add("website", WebsiteUrl);
            if (!string.IsNullOrEmpty(Gender)) claims.Add("gender", Gender);
            if (Birthdate.HasValue) claims.Add("birthdate", Birthdate.Value.ToString("yyyy-MM-dd"));
            if (!string.IsNullOrEmpty(Locale)) claims.Add("locale", Locale);
            if (!string.IsNullOrEmpty(ZoneInfo)) claims.Add("zoneinfo", ZoneInfo);

            // 邮箱
            if (!string.IsNullOrEmpty(Email)) claims.Add("email", Email);
            claims.Add("email_verified", EmailConfirmed);

            // 手机
            if (!string.IsNullOrEmpty(PhoneNumber)) claims.Add("phone_number", PhoneNumber);
            claims.Add("phone_number_verified", PhoneNumberConfirmed);

            // 地址
            if (Address != null)
            {
                claims.Add("address", new Dictionary<string, object>
                {
                    ["formatted"] = Address.ToString(),
                    ["street_address"] = Address.StreetAddress ?? "",
                    ["locality"] = Address.Locality ?? "",
                    ["region"] = Address.Region ?? "",
                    ["postal_code"] = Address.PostalCode ?? "",
                    ["country"] = Address.Country ?? ""
                });
            }

            return claims;
        }

        /// <summary>
        /// 获取用户信息（用于 UserInfo 端点）
        /// 与 GetOidcClaims 配合 OpenIddict 使用
        /// </summary>
        public System.Security.Claims.ClaimsPrincipal ToClaimsPrincipal()
        {
            var claims = GetOidcClaims()
                .Select(kv => new System.Security.Claims.Claim(kv.Key, kv.Value.ToString() ?? string.Empty))
                .ToList();

            var identity = new System.Security.Claims.ClaimsIdentity(
                claims,
                "Identity.Application",
                "name",
                "role");

            return new System.Security.Claims.ClaimsPrincipal(identity);
        }
    }
}
