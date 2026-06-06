namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 短信验证码实体 - 用于手机号登录、绑定、重置密码等场景
    /// 采用充血模型设计，通过工厂方法创建，属性不可变
    /// </summary>
    public class SmsCode
    {
        /// <summary>
        /// 无参构造函数 - EF Core 需要（private 确保外部不能直接 new）
        /// </summary>
        private SmsCode() { }

        /// <summary>
        /// 私有构造函数 - 由工厂方法调用
        /// </summary>
        private SmsCode(
            string phoneNumber,
            string code,
            string type,
            DateTimeOffset expiresAt)
        {
            Id = Guid.NewGuid();
            PhoneNumber = phoneNumber;
            Code = code;
            Type = type;
            ExpiresAt = expiresAt;
            CreatedAt = DateTimeOffset.UtcNow;
            IsUsed = false;
            AttemptCount = 0;
            IsActive = true;
        }

        // ========== 属性（全部 private set） ==========

        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; private set; }

        /// <summary>
        /// 手机号（E.164 格式，如 +8613800000000）
        /// </summary>
        public string PhoneNumber { get; private set; } = string.Empty;

        /// <summary>
        /// 验证码（6位数字）
        /// </summary>
        public string Code { get; private set; } = string.Empty;

        /// <summary>
        /// 验证码类型：login, register, bind, reset_password
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
        /// 尝试次数（用于防暴力破解）
        /// </summary>
        public int AttemptCount { get; private set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }

        /// <summary>
        /// 是否激活（软删除）
        /// </summary>
        public bool IsActive { get; private set; } = true;

        // ========== 工厂方法 ==========

        /// <summary>
        /// 创建新的短信验证码
        /// </summary>
        /// <param name="phoneNumber">手机号（E.164 格式）</param>
        /// <param name="code">验证码（通常为6位数字）</param>
        /// <param name="type">验证码类型：login、register、bind、reset_password</param>
        /// <param name="expireMinutes">有效期（分钟），默认5分钟</param>
        /// <returns>短信验证码实体</returns>
        public static SmsCode Create(
            string phoneNumber,
            string code,
            string type,
            int expireMinutes = 5)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                throw new ArgumentException("手机号不能为空", nameof(phoneNumber));

            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentException("验证码不能为空", nameof(code));

            if (code.Length != 6 || !code.All(char.IsDigit))
                throw new ArgumentException("验证码必须为6位数字", nameof(code));

            if (expireMinutes <= 0)
                throw new ArgumentException("有效期必须大于0", nameof(expireMinutes));

            return new SmsCode(
                phoneNumber: phoneNumber,
                code: code,
                type: type,
                expiresAt: DateTimeOffset.UtcNow.AddMinutes(expireMinutes));
        }

        /// <summary>
        /// 创建新的短信验证码（带自定义过期时间）
        /// </summary>
        /// <param name="phoneNumber">手机号（E.164 格式）</param>
        /// <param name="code">验证码（通常为6位数字）</param>
        /// <param name="type">验证码类型：login、register、bind、reset_password</param>
        /// <param name="expiresAt">自定义过期时间</param>
        /// <returns>短信验证码实体</returns>
        public static SmsCode CreateWithExpiry(
            string phoneNumber,
            string code,
            string type,
            DateTimeOffset expiresAt)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                throw new ArgumentException("手机号不能为空", nameof(phoneNumber));

            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentException("验证码不能为空", nameof(code));

            if (code.Length != 6 || !code.All(char.IsDigit))
                throw new ArgumentException("验证码必须为6位数字", nameof(code));

            if (expiresAt <= DateTimeOffset.UtcNow)
                throw new ArgumentException("过期时间必须在当前时间之后", nameof(expiresAt));

            return new SmsCode(
                phoneNumber: phoneNumber,
                code: code,
                type: type,
                expiresAt: expiresAt);
        }

        // ========== 业务方法 ==========

        /// <summary>
        /// 检查验证码是否有效（未使用、未过期、未删除）
        /// </summary>
        public bool IsValid()
        {
            return !IsUsed && ExpiresAt > DateTimeOffset.UtcNow && IsActive;
        }

        /// <summary>
        /// 检查验证码是否已过期
        /// </summary>
        public bool IsExpired()
        {
            return ExpiresAt <= DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 检查验证码是否已被使用
        /// </summary>
        public bool IsUsedAlready()
        {
            return IsUsed;
        }

        /// <summary>
        /// 标记为已使用
        /// </summary>
        public void MarkUsed()
        {
            if (IsUsed)
                throw new InvalidOperationException("验证码已被使用，不能重复使用");

            if (!IsValid())
                throw new InvalidOperationException("验证码已失效，不能使用");

            IsUsed = true;
            UsedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 增加尝试次数
        /// </summary>
        /// <returns>当前尝试次数</returns>
        public int IncrementAttempt()
        {
            AttemptCount++;
            return AttemptCount;
        }

        /// <summary>
        /// 检查是否超过最大尝试次数
        /// </summary>
        /// <param name="maxAttempts">最大尝试次数，默认5次</param>
        public bool IsExceedMaxAttempts(int maxAttempts = 5)
        {
            return AttemptCount >= maxAttempts;
        }

        /// <summary>
        /// 验证验证码（核心业务方法）
        /// </summary>
        /// <param name="inputCode">用户输入的验证码</param>
        /// <param name="maxAttempts">最大尝试次数，默认5次</param>
        /// <returns>验证结果</returns>
        public SmsCodeVerificationResult Verify(string inputCode, int maxAttempts = 5)
        {
            // 1. 检查是否已被使用
            if (IsUsed)
                return SmsCodeVerificationResult.AlreadyUsed;

            // 2. 检查是否已过期
            if (IsExpired())
                return SmsCodeVerificationResult.Expired;

            // 3. 检查是否已软删除
            if (!IsActive)
                return SmsCodeVerificationResult.Inactive;

            // 4. 增加尝试次数
            IncrementAttempt();

            // 5. 检查是否超过最大尝试次数
            if (IsExceedMaxAttempts(maxAttempts))
                return SmsCodeVerificationResult.TooManyAttempts;

            // 6. 验证验证码是否匹配
            if (Code != inputCode)
                return SmsCodeVerificationResult.CodeMismatch;

            // 7. 验证成功，标记为已使用
            MarkUsed();

            return SmsCodeVerificationResult.Success;
        }

        /// <summary>
        /// 软删除
        /// </summary>
        public void SoftDelete()
        {
            if (!IsActive)
                return;

            IsActive = false;
        }

        /// <summary>
        /// 恢复软删除
        /// </summary>
        public void Restore()
        {
            if (IsActive)
                return;

            IsActive = true;
        }

        /// <summary>
        /// 获取剩余有效秒数
        /// </summary>
        public int GetRemainingSeconds()
        {
            if (!IsValid())
                return 0;

            var remaining = ExpiresAt - DateTimeOffset.UtcNow;
            return remaining.TotalSeconds > 0 ? (int)remaining.TotalSeconds : 0;
        }

        /// <summary>
        /// 获取剩余有效分钟数（用于显示）
        /// </summary>
        public int GetRemainingMinutes()
        {
            var seconds = GetRemainingSeconds();
            return (int)Math.Ceiling(seconds / 60.0);
        }

        /// <summary>
        /// 获取验证码类型的友好名称
        /// </summary>
        public string GetFriendlyTypeName()
        {
            return Type switch
            {
                "login" => "登录验证",
                "register" => "注册验证",
                "bind" => "绑定手机",
                "reset_password" => "重置密码",
                _ => Type
            };
        }

        /// <summary>
        /// 转换为字符串（用于调试）
        /// </summary>
        public override string ToString()
        {
            return $"[{Type}] {PhoneNumber}: {Code} (有效期至 {ExpiresAt:yyyy-MM-dd HH:mm:ss})";
        }
    }

    /// <summary>
    /// 短信验证码验证结果
    /// </summary>
    public enum SmsCodeVerificationResult
    {
        /// <summary>
        /// 验证成功
        /// </summary>
        Success,

        /// <summary>
        /// 验证码已被使用
        /// </summary>
        AlreadyUsed,

        /// <summary>
        /// 验证码已过期
        /// </summary>
        Expired,

        /// <summary>
        /// 验证码已失效（软删除）
        /// </summary>
        Inactive,

        /// <summary>
        /// 尝试次数过多
        /// </summary>
        TooManyAttempts,

        /// <summary>
        /// 验证码不匹配
        /// </summary>
        CodeMismatch
    }
}
