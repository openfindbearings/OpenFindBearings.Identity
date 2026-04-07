using OpenFindBearings.Identity.Data.Enums;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 用户第三方登录绑定表
    /// 记录用户绑定的第三方账号（微信、支付宝等）
    /// </summary>
    [Table("UserLoginBindings")]
    public class UserLoginBinding
    {
        /// <summary>
        /// 主键
        /// </summary>
        [Key]
        public long Id { get; set; }

        /// <summary>
        /// 用户ID（关联 User.Sub）
        /// </summary>
        [MaxLength(255)]
        [Required]
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// 登录提供者类型
        /// </summary>
        [Required]
        public LoginProvider Provider { get; set; }

        /// <summary>
        /// 第三方平台的唯一标识符
        /// 微信: openid
        /// 支付宝: user_id
        /// </summary>
        [MaxLength(255)]
        [Required]
        public string ProviderUserId { get; set; } = string.Empty;

        /// <summary>
        /// 第三方平台的 UnionId（微信体系特有，用于跨应用统一用户）
        /// </summary>
        [MaxLength(255)]
        public string? UnionId { get; set; }

        /// <summary>
        /// 第三方平台的昵称
        /// </summary>
        [MaxLength(100)]
        public string? ProviderNickname { get; set; }

        /// <summary>
        /// 第三方平台的头像URL
        /// </summary>
        [MaxLength(500)]
        public string? ProviderAvatarUrl { get; set; }

        /// <summary>
        /// 第三方平台返回的原始数据（JSON格式）
        /// </summary>
        [Column(TypeName = "jsonb")]
        public string? RawData { get; set; }

        /// <summary>
        /// 绑定时间
        /// </summary>
        public DateTimeOffset BindTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 最后使用时间
        /// </summary>
        public DateTimeOffset? LastUsedTime { get; set; }

        /// <summary>
        /// 是否已解绑
        /// </summary>
        public bool IsUnbound { get; set; } = false;

        /// <summary>
        /// 解绑时间
        /// </summary>
        public DateTimeOffset? UnbindTime { get; set; }

        // 导航属性
        [ForeignKey(nameof(UserId))]
        public virtual User? User { get; set; }
    }
}
