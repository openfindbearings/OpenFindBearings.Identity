using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public interface ISmsVerificationCodeRepository
    {
        Task<SmsVerificationCode?> GetLatestValidCodeAsync(string phoneNumber, string type);
        Task<SmsVerificationCode> AddAsync(SmsVerificationCode code);
        Task UpdateAsync(SmsVerificationCode code);
        Task<int> GetAttemptCountAsync(string phoneNumber, string type, DateTimeOffset since);
    }
}
