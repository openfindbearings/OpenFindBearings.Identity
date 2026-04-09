using OpenFindBearings.Identity.Models.Enums;

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
        public LoginProviders Provider { get; private set; }
        
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
        public static UserLoginBinding Create(Guid userId, LoginProviders provider, string providerUserId, string? unionId = null)
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

        internal static UserLoginBinding CreateFromSeed(Guid userId, LoginProviders provider, string providerUserId, string? unionId,
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
}
