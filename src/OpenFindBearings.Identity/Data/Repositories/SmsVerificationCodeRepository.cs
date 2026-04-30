using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public class SmsVerificationCodeRepository : ISmsVerificationCodeRepository
    {
        private readonly ApplicationDbContext _context;

        public SmsVerificationCodeRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<SmsVerificationCode?> GetLatestValidCodeAsync(string phoneNumber, string type)
        {
            var now = DateTimeOffset.UtcNow;
            return await _context.SmsVerificationCodes
                .Where(c => c.PhoneNumber == phoneNumber
                            && c.Type == type
                            && !c.IsUsed
                            && c.ExpiresAt > now)
                .OrderByDescending(c => c.CreatedAt)
                .FirstOrDefaultAsync();
        }

        public async Task<SmsVerificationCode> AddAsync(SmsVerificationCode code)
        {
            _context.SmsVerificationCodes.Add(code);
            await _context.SaveChangesAsync();
            return code;
        }

        public async Task UpdateAsync(SmsVerificationCode code)
        {
            _context.SmsVerificationCodes.Update(code);
            await _context.SaveChangesAsync();
        }

        public async Task<int> GetAttemptCountAsync(string phoneNumber, string type, DateTimeOffset since)
        {
            return await _context.SmsVerificationCodes
                .CountAsync(c => c.PhoneNumber == phoneNumber
                                && c.Type == type
                                && c.CreatedAt >= since);
        }
    }
}
