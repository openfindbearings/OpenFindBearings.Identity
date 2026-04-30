using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ViewModels;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    public interface IUserRepository
    {
        Task<User?> GetBySubAsync(string sub);
        Task<User?> GetByIdAsync(Guid id);
        Task<User?> GetByUsernameAsync(string username);
        Task<User?> GetByEmailAsync(string email);
        Task<User?> GetByPhoneNumberAsync(string phoneNumber);
        Task<User> AddAsync(User user);
        Task UpdateAsync(User user);
        Task<bool> ExistsByUsernameAsync(string username);
        Task<bool> ExistsByEmailAsync(string email);
        Task<bool> ExistsByPhoneNumberAsync(string phoneNumber);
        Task<PaginatedList<User>> GetPaginatedListAsync(int pageIndex, int pageSize, string? searchKeyword = null);
    }
}
