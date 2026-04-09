namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 用户登录日志 - 记录所有登录行为，用于统计和安全审计
    /// </summary>
    public sealed class UserLoginLog
    {
        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; private set; }
        
        /// <summary>
        /// 用户ID
        /// </summary>
        public Guid UserId { get; private set; }
        
        /// <summary>
        /// 登录类型
        /// password/sms/wechat/alipay/refresh_token/client_credentials
        /// </summary>
        public string LoginType { get; private set; }
        
        /// <summary>
        /// 登录状态
        /// </summary>
        public string Status { get; private set; } = "success";
        
        /// <summary>
        /// 失败原因
        /// </summary>
        public string? FailureReason { get; private set; }
        
        /// <summary>
        /// 客户端ID
        /// </summary>
        public string? ClientId { get; private set; }
        
        /// <summary>
        /// IP地址
        /// </summary>
        public string? IpAddress { get; private set; }
        
        /// <summary>
        /// 用户代理
        /// </summary>
        public string? UserAgent { get; private set; }
        
        /// <summary>
        /// 设备类型
        /// </summary>
        public string? DeviceType { get; private set; }
        
        /// <summary>
        /// 设备标识符
        /// </summary>
        public string? DeviceId { get; private set; }
        
        /// <summary>
        /// 登录时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }

        /// <summary>
        /// 无参构造函数 - 仅供 EF Core 使用
        /// </summary>
        private UserLoginLog() { }

        /// <summary>
        /// 创建登录日志
        /// </summary>
        public static UserLoginLog Create(Guid userId, string loginType, string? clientId = null, string? ipAddress = null)
        {
            return new UserLoginLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                LoginType = loginType,
                ClientId = clientId,
                IpAddress = ipAddress,
                Status = "success",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        internal static UserLoginLog CreateFromSeed(Guid userId, string loginType, string status, string? failureReason,
            string? clientId, string? ipAddress, string? userAgent, string? deviceType, string? deviceId, DateTimeOffset createdAt)
        {
            return new UserLoginLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                LoginType = loginType,
                Status = status,
                FailureReason = failureReason,
                ClientId = clientId,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                DeviceType = deviceType,
                DeviceId = deviceId,
                CreatedAt = createdAt
            };
        }

        /// <summary>
        /// 标记为失败
        /// </summary>
        public void MarkFailed(string? reason = null)
        {
            Status = "failed";
            FailureReason = reason;
        }
    }
}
