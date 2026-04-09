namespace OpenFindBearings.Identity.Models.Enums
{
    /// <summary>
    /// 登录提供者类型枚举
    /// 包含密码登录、短信验证码、第三方登录、刷新令牌、客户端凭证等
    /// </summary>
    public enum LoginProviders
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
