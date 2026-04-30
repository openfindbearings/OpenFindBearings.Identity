using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    /// <summary>
    /// 系统配置仓储实现
    /// </summary>
    public class SystemConfigRepository : ISystemConfigRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly DbSet<SystemConfig> _dbSet;

        public SystemConfigRepository(ApplicationDbContext context)
        {
            _context = context;
            _dbSet = context.Set<SystemConfig>();
        }

        public async Task<SystemConfig?> GetByKeyAsync(string key, CancellationToken ct = default)
        {
            return await _dbSet.FirstOrDefaultAsync(x => x.Key == key, ct);
        }

        public async Task<IReadOnlyList<SystemConfig>> GetAllAsync(CancellationToken ct = default)
        {
            return await _dbSet.OrderBy(x => x.Key).ToListAsync(ct);
        }

        public async Task AddAsync(SystemConfig config, CancellationToken ct = default)
        {
            await _dbSet.AddAsync(config, ct);
        }

        public Task UpdateAsync(SystemConfig config, CancellationToken ct = default)
        {
            config.UpdatedAt = DateTimeOffset.UtcNow;
            _dbSet.Update(config);
            return Task.CompletedTask;
        }

        public Task DeleteAsync(SystemConfig config, CancellationToken ct = default)
        {
            _dbSet.Remove(config);
            return Task.CompletedTask;
        }

        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            return await _dbSet.AnyAsync(x => x.Key == key, ct);
        }
    }
}
