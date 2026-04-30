using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ViewModels;
using System.Security.Claims;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    public interface IScopeRepository
    {
        Task<Scope?> GetByNameAsync(string name);
        Task<IReadOnlyList<Scope>> GetAllAsync();
        Task CreateAsync(Scope scope);
        Task UpdateAsync(Scope scope);
        Task DeleteAsync(Scope scope);
        Task<bool> ExistsByNameAsync(string name);
        Task<PaginatedList<Scope>> GetPaginatedListAsync(int pageIndex, int pageSize, string? searchKeyword = null);
        Task<List<string>> ListResourcesAsync(ClaimsIdentity identity);
    }
}
