using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Enums;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public class UserLoginBindingRepository : IUserLoginBindingRepository
    {
        private readonly ApplicationDbContext _context;

        public UserLoginBindingRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<UserLoginBinding?> GetByUserAndProviderAsync(Guid userId, LoginProviders provider)
        {
            return await _context.UserLoginBindings
                .FirstOrDefaultAsync(b => b.UserId == userId && b.Provider == provider && !b.IsUnbound);
        }

        public async Task<UserLoginBinding?> GetByProviderAndUserIdAsync(LoginProviders provider, string providerUserId)
        {
            return await _context.UserLoginBindings
                .FirstOrDefaultAsync(b => b.Provider == provider && b.ProviderUserId == providerUserId && !b.IsUnbound);
        }

        public async Task<List<UserLoginBinding>> GetByUserIdAsync(Guid userId)
        {
            return await _context.UserLoginBindings
                .Where(b => b.UserId == userId && !b.IsUnbound)
                .ToListAsync();
        }

        public async Task<UserLoginBinding> AddAsync(UserLoginBinding binding)
        {
            _context.UserLoginBindings.Add(binding);
            await _context.SaveChangesAsync();
            return binding;
        }

        public async Task UpdateAsync(UserLoginBinding binding)
        {
            _context.UserLoginBindings.Update(binding);
            await _context.SaveChangesAsync();
        }
    }
}
