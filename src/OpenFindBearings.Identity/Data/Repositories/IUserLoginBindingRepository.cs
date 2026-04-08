using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public interface IUserLoginBindingRepository
    {
        Task<UserLoginBinding?> GetByUserAndProviderAsync(Guid userId, LoginProvider provider);
        Task<UserLoginBinding?> GetByProviderAndUserIdAsync(LoginProvider provider, string providerUserId);
        Task<List<UserLoginBinding>> GetByUserIdAsync(Guid userId);
        Task<UserLoginBinding> AddAsync(UserLoginBinding binding);
        Task UpdateAsync(UserLoginBinding binding);
    }
}
