namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 短信验证码 - 用于手机号登录/绑定/重置密码等场景
    /// </summary>
    public sealed class SmsVerificationCode
    {
        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; private set; }
        
        /// <summary>
        /// 手机号（E.164格式）
        /// </summary>
        public string PhoneNumber { get; private set; }
        
        /// <summary>
        /// 验证码
        /// </summary>
        public string Code { get; private set; }
        
        /// <summary>
        /// 验证码类型
        /// </summary>
        public string Type { get; private set; } = "login";
        
        /// <summary>
        /// 是否已使用
        /// </summary>
        public bool IsUsed { get; private set; }
        
        /// <summary>
        /// 使用时间
        /// </summary>
        public DateTimeOffset? UsedAt { get; private set; }
        
        /// <summary>
        /// 过期时间
        /// </summary>
        public DateTimeOffset ExpiresAt { get; private set; }
        
        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }
        
        /// <summary>
        /// 尝试次数
        /// </summary>
        public int AttemptCount { get; private set; }

        /// <summary>
        /// 无参构造函数 - 仅供 EF Core 使用
        /// </summary>
        private SmsVerificationCode() { }

        /// <summary>
        /// 创建新验证码
        /// </summary>
        public static SmsVerificationCode Create(string phoneNumber, string code, string type, int expireMinutes = 5)
        {
            return new SmsVerificationCode
            {
                Id = Guid.NewGuid(),
                PhoneNumber = phoneNumber,
                Code = code,
                Type = type,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(expireMinutes),
                IsUsed = false,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        internal static SmsVerificationCode CreateFromSeed(string phoneNumber, string code, string type, bool isUsed,
            DateTimeOffset? usedAt, DateTimeOffset expiresAt, DateTimeOffset createdAt, int attemptCount)
        {
            return new SmsVerificationCode
            {
                Id = Guid.NewGuid(),
                PhoneNumber = phoneNumber,
                Code = code,
                Type = type,
                IsUsed = isUsed,
                UsedAt = usedAt,
                ExpiresAt = expiresAt,
                CreatedAt = createdAt,
                AttemptCount = attemptCount
            };
        }

        /// <summary>
        /// 标记为已使用
        /// </summary>
        public void MarkUsed()
        {
            IsUsed = true;
            UsedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 检查是否有效
        /// </summary>
        public bool IsValid()
        {
            return !IsUsed && ExpiresAt > DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 增加尝试次数
        /// </summary>
        public void IncrementAttempt()
        {
            AttemptCount++;
        }
    }
}
