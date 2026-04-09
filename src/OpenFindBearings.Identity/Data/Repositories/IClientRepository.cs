using OpenFindBearings.Identity.Models;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public interface IClientRepository
    {
        Task<Client?> GetByClientIdAsync(string clientId);
        Task<IReadOnlyList<Client>> GetAllAsync();
        Task CreateAsync(Client client);
        Task UpdateAsync(Client client);
        Task DeleteAsync(Client client);
        Task<bool> ExistsByClientIdAsync(string clientId);
        Task<PaginatedList<Client>> GetPaginatedListAsync(int pageIndex, int pageSize, string? searchKeyword = null);
    }
}
