namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 短信验证码服务接口 - 发送和验证短信验证码
    /// </summary>
    public interface ISmsCodeService
    {
        /// <summary>
        /// 发送验证码
        /// </summary>
        /// <param name="phoneNumber">手机号</param>
        /// <param name="type">类型（login, register, bind, reset_password）</param>
        /// <returns>是否发送成功</returns>
        Task<bool> SendAsync(string phoneNumber, string type, CancellationToken ct = default);

        /// <summary>
        /// 验证验证码
        /// </summary>
        /// <param name="phoneNumber">手机号</param>
        /// <param name="code">验证码</param>
        /// <param name="type">类型</param>
        /// <returns>是否有效</returns>
        Task<bool> ValidateAsync(string phoneNumber, string code, string type, CancellationToken ct = default);

        /// <summary>
        /// 检查发送频率限制
        /// </summary>
        Task<bool> CanSendAsync(string phoneNumber, string type, CancellationToken ct = default);
    }
}
