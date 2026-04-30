using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models;
using OpenFindBearings.Identity.Models.Entities;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public class ClientRepository : IClientRepository
    {
        private readonly ApplicationDbContext _context;
        private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

        public ClientRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<Client?> GetByClientIdAsync(string clientId)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreApplication>()
                .FirstOrDefaultAsync(x => x.ClientId == clientId);
            return entity != null ? MapToClient(entity) : null;
        }

        public async Task<IReadOnlyList<Client>> GetAllAsync()
        {
            var entities = await _context.Set<OpenIddictEntityFrameworkCoreApplication>()
                .ToListAsync();
            return entities.Select(MapToClient).ToList();
        }

        public async Task CreateAsync(Client client)
        {
            var entity = MapToEntity(client);
            _context.Set<OpenIddictEntityFrameworkCoreApplication>().Add(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Client client)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreApplication>()
                .FirstOrDefaultAsync(x => x.ClientId == client.ClientId);
            if (entity != null)
            {
                entity.DisplayName = client.DisplayName;
                entity.DisplayNames = client.Permissions != null ? JsonSerializer.Serialize(client.Permissions) : null;
                entity.ClientSecret = client.ClientSecret;
                entity.ClientType = client.ClientType;
                entity.ConsentType = client.ConsentType;
                entity.RedirectUris = client.RedirectUris != null ? JsonSerializer.Serialize(client.RedirectUris.Select(u => u.ToString()).ToHashSet()) : null;
                entity.PostLogoutRedirectUris = client.PostLogoutRedirectUris != null ? JsonSerializer.Serialize(client.PostLogoutRedirectUris.Select(u => u.ToString()).ToHashSet()) : null;
                entity.Permissions = client.Permissions != null ? JsonSerializer.Serialize(client.Permissions) : null;
                await _context.SaveChangesAsync();
            }
        }

        public async Task DeleteAsync(Client client)
        {
            var entity = await _context.Set<OpenIddictEntityFrameworkCoreApplication>()
                .FirstOrDefaultAsync(x => x.ClientId == client.ClientId);
            if (entity != null)
            {
                _context.Set<OpenIddictEntityFrameworkCoreApplication>().Remove(entity);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ExistsByClientIdAsync(string clientId)
        {
            return await _context.Set<OpenIddictEntityFrameworkCoreApplication>()
                .AnyAsync(x => x.ClientId == clientId);
        }

        public async Task<PaginatedList<Client>> GetPaginatedListAsync(int pageIndex, int pageSize, string? searchKeyword = null)
        {
            var query = _context.Set<OpenIddictEntityFrameworkCoreApplication>().AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchKeyword))
            {
                var keyword = searchKeyword.Trim().ToLower();
                query = query.Where(x => 
                    (x.ClientId != null && x.ClientId.ToLower().Contains(keyword)) ||
                    (x.DisplayName != null && x.DisplayName.ToLower().Contains(keyword)));
            }

            var totalCount = await query.CountAsync();
            var entities = await query
                .OrderByDescending(x => x.ClientId)
                .Skip((pageIndex - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var items = entities.Select(MapToClient).ToList();
            return new PaginatedList<Client>(items, totalCount, pageIndex, pageSize);
        }

        private static Client MapToClient(OpenIddictEntityFrameworkCoreApplication entity)
        {
            var permissions = entity.Permissions != null 
                ? JsonSerializer.Deserialize<HashSet<string>>(entity.Permissions, JsonOptions) 
                : [];

            var redirectUris = entity.RedirectUris != null 
                ? JsonSerializer.Deserialize<HashSet<string>>(entity.RedirectUris, JsonOptions)?.Select(u => new Uri(u, UriKind.RelativeOrAbsolute)).ToHashSet()
                : [];

            var postLogoutRedirectUris = entity.PostLogoutRedirectUris != null 
                ? JsonSerializer.Deserialize<HashSet<string>>(entity.PostLogoutRedirectUris, JsonOptions)?.Select(u => new Uri(u, UriKind.RelativeOrAbsolute)).ToHashSet()
                : [];

            return Client.Create(
                clientId: entity.ClientId ?? string.Empty,
                clientSecret: entity.ClientSecret,
                displayName: entity.DisplayName ?? string.Empty,
                clientType: entity.ClientType,
                consentType: entity.ConsentType,
                permissions: permissions,
                redirectUris: redirectUris,
                postLogoutRedirectUris: postLogoutRedirectUris,
                isActive: true
            );
        }

        private static OpenIddictEntityFrameworkCoreApplication MapToEntity(Client client)
        {
            return new OpenIddictEntityFrameworkCoreApplication
            {
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                DisplayName = client.DisplayName,
                ClientType = client.ClientType,
                ConsentType = client.ConsentType,
                RedirectUris = client.RedirectUris != null ? JsonSerializer.Serialize(client.RedirectUris.Select(u => u.ToString()).ToHashSet()) : null,
                PostLogoutRedirectUris = client.PostLogoutRedirectUris != null ? JsonSerializer.Serialize(client.PostLogoutRedirectUris.Select(u => u.ToString()).ToHashSet()) : null,
                Permissions = client.Permissions != null ? JsonSerializer.Serialize(client.Permissions) : null
            };
        }
    }
}
