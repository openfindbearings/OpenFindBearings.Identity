namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 用户第三方登录绑定 - 记录用户绑定的第三方账号（微信、支付宝等）
    /// </summary>
    public sealed class UserLoginBinding
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
        /// 登录提供者类型
        /// </summary>
        public LoginProvider Provider { get; private set; }
        
        /// <summary>
        /// 第三方平台的用户唯一标识
        /// 微信: openid，支付宝: user_id
        /// </summary>
        public string ProviderUserId { get; private set; }
        
        /// <summary>
        /// UnionId（微信体系特有）
        /// </summary>
        public string? UnionId { get; private set; }
        
        /// <summary>
        /// 第三方平台的昵称
        /// </summary>
        public string? ProviderNickname { get; private set; }
        
        /// <summary>
        /// 第三方平台的头像URL
        /// </summary>
        public string? ProviderAvatarUrl { get; private set; }
        
        /// <summary>
        /// 第三方平台返回的原始数据
        /// </summary>
        public string? RawData { get; private set; }
        
        /// <summary>
        /// 绑定时间
        /// </summary>
        public DateTimeOffset BindTime { get; private set; }
        
        /// <summary>
        /// 最后使用时间
        /// </summary>
        public DateTimeOffset? LastUsedTime { get; private set; }
        
        /// <summary>
        /// 是否已解绑
        /// </summary>
        public bool IsUnbound { get; private set; }
        
        /// <summary>
        /// 解绑时间
        /// </summary>
        public DateTimeOffset? UnbindTime { get; private set; }

        /// <summary>
        /// 无参构造函数 - 仅供 EF Core 使用
        /// </summary>
        private UserLoginBinding() { }

        /// <summary>
        /// 创建新的第三方登录绑定
        /// </summary>
        public static UserLoginBinding Create(Guid userId, LoginProvider provider, string providerUserId, string? unionId = null)
        {
            return new UserLoginBinding
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Provider = provider,
                ProviderUserId = providerUserId,
                UnionId = unionId,
                BindTime = DateTimeOffset.UtcNow,
                IsUnbound = false
            };
        }

        internal static UserLoginBinding CreateFromSeed(Guid userId, LoginProvider provider, string providerUserId, string? unionId,
            string? providerNickname, string? providerAvatarUrl, string? rawData, DateTimeOffset bindTime,
            DateTimeOffset? lastUsedTime, bool isUnbound, DateTimeOffset? unbindTime)
        {
            return new UserLoginBinding
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Provider = provider,
                ProviderUserId = providerUserId,
                UnionId = unionId,
                ProviderNickname = providerNickname,
                ProviderAvatarUrl = providerAvatarUrl,
                RawData = rawData,
                BindTime = bindTime,
                LastUsedTime = lastUsedTime,
                IsUnbound = isUnbound,
                UnbindTime = unbindTime
            };
        }

        /// <summary>
        /// 记录最后使用时间
        /// </summary>
        public void RecordUsage()
        {
            LastUsedTime = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 解绑
        /// </summary>
        public void Unbind()
        {
            IsUnbound = true;
            UnbindTime = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 检查是否可用
        /// </summary>
        public bool IsAvailable()
        {
            return !IsUnbound;
        }
    }

    /// <summary>
    /// 登录提供者类型枚举
    /// 包含密码登录、短信验证码、第三方登录、刷新令牌、客户端凭证等
    /// </summary>
    public enum LoginProvider
    {
        /// <summary>
        /// 用户名/邮箱/手机号 + 密码登录
        /// </summary>
        Password = 0,

        /// <summary>
        /// 手机号 + 短信验证码登录
        /// </summary>
        Sms = 100,
        
        /// <summary>
        /// 本机号码一键登录（运营商网关）
        /// </summary>
        PhoneGateway = 101,
        
        /// <summary>
        /// 微信登录（通用）
        /// </summary>
        WeChat = 102,
        
        /// <summary>
        /// 微信小程序登录
        /// </summary>
        WeChatMiniProgram = 103,
        
        /// <summary>
        /// 微信Web扫码登录
        /// </summary>
        WeChatWeb = 104,
        
        /// <summary>
        /// QQ登录
        /// </summary>
        QQ = 105,
        
        /// <summary>
        /// 支付宝登录
        /// </summary>
        Alipay = 106,
        
        /// <summary>
        /// 生物识别登录
        /// </summary>
        Biometric = 107,

        /// <summary>
        /// 刷新令牌
        /// </summary>
        RefreshToken = 200,
        
        /// <summary>
        /// 客户端凭证（服务间调用）
        /// </summary>
        ClientCredentials = 201
    }
}
