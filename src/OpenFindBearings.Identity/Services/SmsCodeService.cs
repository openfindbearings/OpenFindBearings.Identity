using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 短信验证码服务实现
    /// </summary>
    public class SmsCodeService : ISmsCodeService
    {
        private readonly ISmsCodeRepository _smsCodeRepo;

        public SmsCodeService(ISmsCodeRepository smsCodeRepo)
        {
            _smsCodeRepo = smsCodeRepo;
        }

        /// <inheritdoc/>
        public async Task<bool> SendAsync(string phoneNumber, string type, CancellationToken ct = default)
        {
            // 检查发送频率（60秒内不能重复发送）
            if (!await CanSendAsync(phoneNumber, type, ct))
            {
                return false;
            }

            // 生成6位随机验证码
            var code = new Random().Next(100000, 999999).ToString();

            // 保存验证码
            await _smsCodeRepo.CreateAsync(phoneNumber, code, type, 5, ct);

            // TODO: 调用短信发送服务
            // await _smsProvider.SendAsync(phoneNumber, $"您的验证码是：{code}");

            return true;
        }

        /// <inheritdoc/>
        public async Task<bool> ValidateAsync(string phoneNumber, string code, string type, CancellationToken ct = default)
        {
            return await _smsCodeRepo.ValidateAndConsumeAsync(phoneNumber, code, type, ct);
        }

        /// <inheritdoc/>
        public async Task<bool> CanSendAsync(string phoneNumber, string type, CancellationToken ct = default)
        {
            var lastSendTime = await _smsCodeRepo.GetLastSendTimeAsync(phoneNumber, type, ct);
            if (!lastSendTime.HasValue) return true;

            // 60秒内不能重复发送
            return (DateTimeOffset.UtcNow - lastSendTime.Value).TotalSeconds >= 60;
        }
    }
}
