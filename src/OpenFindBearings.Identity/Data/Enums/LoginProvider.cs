namespace OpenFindBearings.Identity.Data.Enums
{
    /// <summary>
    /// 第三方登录提供者类型
    /// </summary>
    public enum LoginProvider
    {
        /// <summary>
        /// 未定义登录类型
        /// </summary>
        Undefined = 0,

        /// <summary>
        /// 微信小程序登录
        /// </summary>
        WeChatMiniProgram = 1,

        /// <summary>
        /// 微信公众号/Web扫码登录
        /// </summary>
        WeChatWeb = 2,

        /// <summary>
        /// 支付宝登录
        /// </summary>
        Alipay = 3,

        /// <summary>
        /// 本机手机号一键登录（运营商网关认证）
        /// </summary>
        PhoneGateway = 4
    }
}
