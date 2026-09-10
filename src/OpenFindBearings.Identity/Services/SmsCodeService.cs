using Microsoft.Extensions.Configuration;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 短信验证码服务实现。
    /// 改动说明：接入真实通道前先支持"开发模式固定码"——当 Sms:DevMode=true 时不发真短信、
    /// 直接用 Sms:DevFixedCode（默认 123456）落库并记日志，配合登录 sms grant 的校验，
    /// 让移动端短信登录在无短信网关的环境下可端到端联调。默认关闭（生产不设该键即安全）。
    /// </summary>
    public class SmsCodeService : ISmsCodeService
    {
        private readonly ISmsCodeRepository _smsCodeRepo;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmsCodeService> _logger;

        public SmsCodeService(
            ISmsCodeRepository smsCodeRepo,
            IConfiguration configuration,
            ILogger<SmsCodeService> logger)
        {
            _smsCodeRepo = smsCodeRepo;
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task<bool> SendAsync(string phoneNumber, string type, CancellationToken ct = default)
        {
            // 检查发送频率（60秒内不能重复发送）
            if (!await CanSendAsync(phoneNumber, type, ct))
            {
                return false;
            }

            // 默认关闭：未显式开启 DevMode 时走"随机码 + 待接入真实通道"，生产不误发固定码
            var devMode = _configuration.GetValue<bool?>("Sms:DevMode") ?? false;
            string code;

            if (devMode)
            {
                code = _configuration["Sms:DevFixedCode"] ?? "123456";
            }
            else
            {
                // Random.Shared 避免短时间高频 new Random() 因时钟种子相同产生重复码
                code = Random.Shared.Next(100000, 999999).ToString();
            }

            // 保存验证码（有效期 5 分钟）
            await _smsCodeRepo.CreateAsync(phoneNumber, code, type, 5, ct);

            if (devMode)
            {
                _logger.LogInformation("[DEV] 短信验证码已生成: Phone={Phone}, Type={Type}, Code={Code}",
                    phoneNumber, type, code);
            }
            else
            {
                // TODO: 接入真实短信通道 ISmsSender 前不发送，仅落库以支持流程联调与回归
                _logger.LogWarning("未配置真实短信通道，验证码仅落库未外发: Phone={Phone}, Type={Type}",
                    phoneNumber, type);
            }

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
