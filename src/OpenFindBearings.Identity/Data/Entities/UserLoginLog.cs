using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OpenFindBearings.Identity.Data.Entities
{
    /// <summary>
    /// 用户登录日志表
    /// 记录所有登录行为，用于统计和安全审计
    /// </summary>
    [Table("UserLoginLogs")]
    public class UserLoginLog
    {
        /// <summary>
        /// 主键
        /// </summary>
        [Key]
        public long Id { get; set; }

        /// <summary>
        /// 用户ID
        /// </summary>
        [MaxLength(255)]
        [Required]
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// 登录类型
        /// password: 密码登录
        /// sms: 短信验证码登录
        /// wechat: 微信登录
        /// alipay: 支付宝登录
        /// phone_gateway: 本机号码一键登录
        /// refresh_token: 刷新令牌
        /// client_credentials: 服务间调用
        /// </summary>
        [MaxLength(30)]
        [Required]
        public string LoginType { get; set; } = string.Empty;

        /// <summary>
        /// 登录状态
        /// success: 成功
        /// failed: 失败
        /// </summary>
        [MaxLength(20)]
        [Required]
        public string Status { get; set; } = "success";

        /// <summary>
        /// 失败原因（仅在失败时记录）
        /// </summary>
        [MaxLength(500)]
        public string? FailureReason { get; set; }

        /// <summary>
        /// 客户端ID（OAuth2 client_id）
        /// </summary>
        [MaxLength(100)]
        public string? ClientId { get; set; }

        /// <summary>
        /// 请求的IP地址
        /// </summary>
        [MaxLength(45)]
        public string? IpAddress { get; set; }

        /// <summary>
        /// 用户代理（浏览器/设备信息）
        /// </summary>
        [MaxLength(500)]
        public string? UserAgent { get; set; }

        /// <summary>
        /// 设备类型
        /// ios, android, web, wechat, unknown
        /// </summary>
        [MaxLength(20)]
        public string? DeviceType { get; set; }

        /// <summary>
        /// 设备标识符（用于识别唯一设备）
        /// </summary>
        [MaxLength(255)]
        public string? DeviceId { get; set; }

        /// <summary>
        /// 登录时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        // 导航属性
        [ForeignKey(nameof(UserId))]
        public virtual User? User { get; set; }
    }
}
