using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Enums;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    public interface IUserLoginBindingRepository
    {
        Task<UserLoginBinding?> GetByUserAndProviderAsync(Guid userId, LoginProviders provider);
        Task<UserLoginBinding?> GetByProviderAndUserIdAsync(LoginProviders provider, string providerUserId);
        Task<List<UserLoginBinding>> GetByUserIdAsync(Guid userId);
        Task<UserLoginBinding> AddAsync(UserLoginBinding binding);
        Task UpdateAsync(UserLoginBinding binding);
    }
}
