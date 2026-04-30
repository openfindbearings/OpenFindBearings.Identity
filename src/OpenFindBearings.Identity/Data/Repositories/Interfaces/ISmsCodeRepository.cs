using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    /// <summary>
    /// 短信验证码仓储接口 - 独立定义
    /// 验证码只能创建、查询、更新状态（使用/失效），不能修改内容
    /// </summary>
    public interface ISmsCodeRepository
    {
        // ========== 添加 ==========

        /// <summary>
        /// 创建验证码
        /// </summary>
        Task<SmsCode> CreateAsync(string phoneNumber, string code, string type, int expireMinutes = 5, CancellationToken cancellationToken = default);

        /// <summary>
        /// 添加验证码
        /// </summary>
        Task AddAsync(SmsCode smsCode, CancellationToken cancellationToken = default);

        // ========== 查询 ==========

        /// <summary>
        /// 根据 ID 获取验证码
        /// </summary>
        Task<SmsCode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据手机号和验证码获取记录
        /// </summary>
        Task<SmsCode?> GetByCodeAsync(string phoneNumber, string code, string type, CancellationToken cancellationToken = default);

        /// <summary>
        /// 根据手机号获取最新的有效验证码
        /// </summary>
        Task<SmsCode?> GetLatestValidCodeAsync(string phoneNumber, string type, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取手机号最近发送验证码的时间（用于发送频率限制）
        /// </summary>
        Task<DateTimeOffset?> GetLastSendTimeAsync(string phoneNumber, string type, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取手机号今日发送次数
        /// </summary>
        Task<int> GetTodaySendCountAsync(string phoneNumber, CancellationToken cancellationToken = default);

        // ========== 更新（只允许更新状态，不允许修改内容）==========

        /// <summary>
        /// 验证并消费验证码
        /// </summary>
        Task<bool> ValidateAndConsumeAsync(string phoneNumber, string code, string type, CancellationToken cancellationToken = default);

        /// <summary>
        /// 使手机号所有未使用的验证码失效
        /// </summary>
        Task InvalidateAllCodesAsync(string phoneNumber, string type, CancellationToken cancellationToken = default);

        /// <summary>
        /// 使验证码失效
        /// </summary>
        Task InvalidateAsync(SmsCode smsCode, CancellationToken cancellationToken = default);

        // ========== 删除（物理删除/软删除）==========

        /// <summary>
        /// 清理过期的验证码（软删除）
        /// </summary>
        Task<int> CleanExpiredCodesAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// 硬删除指定验证码
        /// </summary>
        Task HardDeleteAsync(SmsCode smsCode, CancellationToken cancellationToken = default);
    }
}
