using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services;

namespace OpenFindBearings.Identity.Data.Repositories
{
    /// <summary>
    /// 短信验证码仓储实现
    /// </summary>
    public class SmsCodeRepository : ISmsCodeRepository
    {
        private readonly ApplicationDbContext _context;

        public SmsCodeRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // ========== 添加 ==========

        public async Task<SmsCode> CreateAsync(string phoneNumber, string code, string type, int expireMinutes = 5, CancellationToken cancellationToken = default)
        {
            var smsCode = SmsCode.Create(phoneNumber, code, type, expireMinutes);
            await AddAsync(smsCode, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            return smsCode;
        }

        public async Task AddAsync(SmsCode smsCode, CancellationToken cancellationToken = default)
        {
            await _context.SmsCodes.AddAsync(smsCode, cancellationToken);
        }

        // ========== 查询 ==========

        public async Task<SmsCode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.SmsCodes.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        }

        /// <summary>
        /// 根据手机号获取最新的有效验证码
        /// </summary>
        public async Task<SmsCode?> GetLatestValidCodeAsync(string phoneNumber, string type, CancellationToken cancellationToken = default)
        {
            return await _context.SmsCodes
                .Where(x => x.PhoneNumber == phoneNumber
                    && x.Type == type
                    && x.IsActive
                    && !x.IsUsed
                    && x.ExpiresAt > DateTimeOffset.UtcNow)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<DateTimeOffset?> GetLastSendTimeAsync(string phoneNumber, string type, CancellationToken cancellationToken = default)
        {
            var lastCode = await _context.SmsCodes
                .Where(x => x.PhoneNumber == phoneNumber
                    && x.Type == type
                    && x.IsActive)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken);

            return lastCode?.CreatedAt;
        }

        public async Task<int> GetTodaySendCountAsync(string phoneNumber, CancellationToken cancellationToken = default)
        {
            // 改动说明（v2.18.0 时间治理）：日发送配额的"今日"从 UTC 零点改为业务日界（默认北京），
        // 修复中国用户凌晨 0-8 点请求消耗"前一天"额度、重置点感知错位的问题
        var today = BusinessClock.TodayUtc;
            var tomorrow = today.AddDays(1);

            return await _context.SmsCodes
                .Where(x => x.PhoneNumber == phoneNumber
                    && x.CreatedAt >= today
                    && x.CreatedAt < tomorrow
                    && x.IsActive)
                .CountAsync(cancellationToken);
        }

        // ========== 更新 ==========

        public async Task<bool> ValidateAndConsumeAsync(string phoneNumber, string code, string type, CancellationToken cancellationToken = default)
        {
            // 改动说明（短信登录上线）：原实现按"手机号 + 提交的验证码"精确查库，
            // 猜错码时查不到任何记录 → 尝试次数永不累加，5 分钟有效期内可无限暴力枚举。
            // 改为先取该手机号该类型最新一条有效验证码，统一在此比对并累计尝试次数，
            // 达到上限（实体默认 5 次）即作废该码，堵住爆破口。
            var smsCode = await _context.SmsCodes
                .Where(x => x.PhoneNumber == phoneNumber
                    && x.Type == type
                    && x.IsActive)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken);

            if (smsCode == null)
            {
                return false;
            }

            // 已被猜满次数：直接软删作废，后续任何输入一律拒绝（需重新获取验证码）
            if (smsCode.IsExceedMaxAttempts())
            {
                smsCode.SoftDelete();
                await _context.SaveChangesAsync(cancellationToken);
                return false;
            }

            // 过期/已用/码不匹配：累计一次失败尝试
            if (!smsCode.IsValid() || smsCode.Code != code)
            {
                smsCode.IncrementAttempt();
                await _context.SaveChangesAsync(cancellationToken);
                return false;
            }

            smsCode.MarkUsed();
            await _context.SaveChangesAsync(cancellationToken);

            return true;
        }

        public async Task InvalidateAllCodesAsync(string phoneNumber, string type, CancellationToken cancellationToken = default)
        {
            var codes = await _context.SmsCodes
                .Where(x => x.PhoneNumber == phoneNumber
                    && x.Type == type
                    && !x.IsUsed
                    && x.IsActive)
                .ToListAsync(cancellationToken);

            foreach (var code in codes)
            {
                code.MarkUsed();
            }

            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task InvalidateAsync(SmsCode smsCode, CancellationToken cancellationToken = default)
        {
            smsCode.MarkUsed();
            await _context.SaveChangesAsync(cancellationToken);
        }

        // ========== 删除 ==========

        public async Task<int> CleanExpiredCodesAsync(CancellationToken cancellationToken = default)
        {
            var expiredCodes = await _context.SmsCodes
                .Where(x => x.IsActive && x.ExpiresAt <= DateTimeOffset.UtcNow)
                .ToListAsync(cancellationToken);

            foreach (var code in expiredCodes)
            {
                code.SoftDelete();
            }

            await _context.SaveChangesAsync(cancellationToken);

            return expiredCodes.Count;
        }

        public async Task HardDeleteAsync(SmsCode smsCode, CancellationToken cancellationToken = default)
        {
            _context.SmsCodes.Remove(smsCode);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}
