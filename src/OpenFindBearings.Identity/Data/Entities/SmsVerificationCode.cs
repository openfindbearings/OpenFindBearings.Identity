using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 短信验证码表
    /// 用于手机号 + 短信验证码登录
    /// </summary>
    [Table("SmsVerificationCodes")]
    public class SmsVerificationCode
    {
        /// <summary>
        /// 主键
        /// </summary>
        [Key]
        public long Id { get; set; }

        /// <summary>
        /// 手机号（E.164格式）
        /// </summary>
        [MaxLength(32)]
        [Required]
        public string PhoneNumber { get; set; } = string.Empty;

        /// <summary>
        /// 验证码（6位数字）
        /// </summary>
        [MaxLength(10)]
        [Required]
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// 验证码类型
        /// login: 登录
        /// bind: 绑定手机号
        /// reset_password: 重置密码
        /// </summary>
        [MaxLength(20)]
        [Required]
        public string Type { get; set; } = "login";

        /// <summary>
        /// 是否已使用
        /// </summary>
        public bool IsUsed { get; set; } = false;

        /// <summary>
        /// 使用时间
        /// </summary>
        public DateTimeOffset? UsedAt { get; set; }

        /// <summary>
        /// 过期时间（创建后5-10分钟）
        /// </summary>
        [Required]
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 尝试次数（防止暴力破解）
        /// </summary>
        public int AttemptCount { get; set; } = 0;
    }
}
