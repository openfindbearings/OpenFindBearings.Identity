using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.Entities;

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

        public async Task<SmsCode?> GetByCodeAsync(string phoneNumber, string code, string type, CancellationToken cancellationToken = default)
        {
            return await _context.SmsCodes
                .FirstOrDefaultAsync(x => x.PhoneNumber == phoneNumber
                    && x.Code == code
                    && x.Type == type
                    && x.IsActive, cancellationToken);
        }

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
            var today = DateTimeOffset.UtcNow.Date;
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
            var smsCode = await GetByCodeAsync(phoneNumber, code, type, cancellationToken);

            if (smsCode == null || !smsCode.IsValid())
            {
                if (smsCode != null)
                {
                    smsCode.IncrementAttempt();
                    await _context.SaveChangesAsync(cancellationToken);
                }
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
