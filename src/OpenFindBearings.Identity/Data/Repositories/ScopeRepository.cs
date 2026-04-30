using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ViewModels;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using System.Security.Claims;
using System.Text.Json;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public class ScopeRepository : IScopeRepository
    {
        private readonly ApplicationDbContext _context;
        private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
        private readonly IOpenIddictScopeManager _scopeManager;

        public ScopeRepository(ApplicationDbContext context, IOpenIddictScopeManager scopeManager)
        {
            _context = context;
            _scopeManager = scopeManager;

        }

        public async Task<Scope?> GetByNameAsync(string name)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreScope>()
                .FirstOrDefaultAsync(x => x.Name == name);
            return entity != null ? MapToScope(entity) : null;
        }

        public async Task<IReadOnlyList<Scope>> GetAllAsync()
        {
            var entities = await _context.Set<OpenIddictEntityFrameworkCoreScope>()
                .ToListAsync();
            return entities.Select(MapToScope).ToList();
        }

        public async Task CreateAsync(Scope scope)
        {
            var entity = MapToEntity(scope);
            _context.Set<OpenIddictEntityFrameworkCoreScope>().Add(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Scope scope)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreScope>()
                .FirstOrDefaultAsync(x => x.Name == scope.Name);
            if (entity != null)
            {
                entity.Description = scope.Description;
                entity.DisplayName = scope.DisplayName;
                entity.Resources = scope.Resources != null ? JsonSerializer.Serialize(scope.Resources) : null;
                await _context.SaveChangesAsync();
            }
        }

        public async Task DeleteAsync(Scope scope)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreScope>()
                .FirstOrDefaultAsync(x => x.Name == scope.Name);
            if (entity != null)
            {
                _context.Set<OpenIddictEntityFrameworkCoreScope>().Remove(entity);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ExistsByNameAsync(string name)
        {
            return await _context.Set<OpenIddictEntityFrameworkCoreScope>()
                .AnyAsync(x => x.Name == name);
        }

        public async Task<PaginatedList<Scope>> GetPaginatedListAsync(int pageIndex, int pageSize, string? searchKeyword = null)
        {
            var query = _context.Set<OpenIddictEntityFrameworkCoreScope>().AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchKeyword))
            {
                var keyword = searchKeyword.Trim().ToLower();
                query = query.Where(x => 
                    (x.Name != null && x.Name.ToLower().Contains(keyword)) ||
                    (x.DisplayName != null && x.DisplayName.ToLower().Contains(keyword)) ||
                    (x.Description != null && x.Description.ToLower().Contains(keyword)));
            }

            var totalCount = await query.CountAsync();
            var entities = await query
                .OrderByDescending(x => x.Name)
                .Skip((pageIndex - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var items = entities.Select(MapToScope).ToList();
            return new PaginatedList<Scope>(items, totalCount, pageIndex, pageSize);
        }

        private static Scope MapToScope(OpenIddictEntityFrameworkCoreScope entity)
        {
            var resources = entity.Resources != null 
                ? JsonSerializer.Deserialize<HashSet<string>>(entity.Resources, JsonOptions)
                : [];

            return Scope.Create(
                name: entity.Name ?? string.Empty,
                description: entity.Description,
                displayName: entity.DisplayName,
                resources: resources,
                isActive: true
            );
        }

        private static OpenIddictEntityFrameworkCoreScope MapToEntity(Scope scope)
        {
            return new OpenIddictEntityFrameworkCoreScope
            {
                Name = scope.Name,
                Description = scope.Description,
                DisplayName = scope.DisplayName,
                Resources = scope.Resources != null ? JsonSerializer.Serialize(scope.Resources) : null
            };
        }

        public async Task<List<string>> ListResourcesAsync(ClaimsIdentity identity)
        {
            return await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync();
        }
    }
}
