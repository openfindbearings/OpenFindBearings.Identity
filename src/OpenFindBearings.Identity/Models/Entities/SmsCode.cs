namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 短信验证码实体 - 用于手机号登录、绑定、重置密码等场景
    /// </summary>
    public class SmsCode
    {
        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// 手机号（E.164 格式，如 +8613800000000）
        /// </summary>
        public string PhoneNumber { get; set; } = string.Empty;

        /// <summary>
        /// 验证码（6位数字）
        /// </summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// 验证码类型：login, register, bind, reset_password
        /// </summary>
        public string Type { get; set; } = "login";

        /// <summary>
        /// 是否已使用
        /// </summary>
        public bool IsUsed { get; set; }

        /// <summary>
        /// 使用时间
        /// </summary>
        public DateTimeOffset? UsedAt { get; set; }

        /// <summary>
        /// 过期时间
        /// </summary>
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>
        /// 尝试次数（用于防暴力破解）
        /// </summary>
        public int AttemptCount { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 是否激活（软删除）
        /// </summary>
        public bool IsActive { get; set; } = true;

        // ========== 工厂方法 ==========

        /// <summary>
        /// 创建新的短信验证码
        /// </summary>
        /// <param name="phoneNumber">手机号</param>
        /// <param name="code">验证码</param>
        /// <param name="type">类型</param>
        /// <param name="expireMinutes">有效期（分钟）</param>
        public static SmsCode Create(string phoneNumber, string code, string type, int expireMinutes = 5)
        {
            return new SmsCode
            {
                PhoneNumber = phoneNumber,
                Code = code,
                Type = type,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(expireMinutes),
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        // ========== 业务方法 ==========

        /// <summary>
        /// 检查验证码是否有效（未使用、未过期、未删除）
        /// </summary>
        public bool IsValid() => !IsUsed && ExpiresAt > DateTimeOffset.UtcNow && IsActive;

        /// <summary>
        /// 标记为已使用
        /// </summary>
        public void MarkUsed()
        {
            IsUsed = true;
            UsedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 增加尝试次数
        /// </summary>
        public void IncrementAttempt() => AttemptCount++;

        /// <summary>
        /// 软删除
        /// </summary>
        public void SoftDelete()
        {
            IsActive = false;
        }
    }
}
