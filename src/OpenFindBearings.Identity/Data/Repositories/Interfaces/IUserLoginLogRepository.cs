using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    public interface IUserLoginLogRepository
    {
        Task<UserLoginLog> AddAsync(UserLoginLog log);
        Task<List<UserLoginLog>> GetByUserIdAsync(Guid userId, int count = 10);
    }
}
