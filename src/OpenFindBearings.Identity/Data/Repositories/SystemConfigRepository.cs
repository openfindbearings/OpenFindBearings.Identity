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

        public SystemConfigRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<SystemConfig?> GetByKeyAsync(string key, CancellationToken ct = default)
        {
            return await _context.SystemConfigs.FirstOrDefaultAsync(x => x.Key == key, ct);
        }

        public async Task<IReadOnlyList<SystemConfig>> GetAllAsync(CancellationToken ct = default)
        {
            return await _context.SystemConfigs.OrderBy(x => x.Key).ToListAsync(ct);
        }

        public async Task AddAsync(SystemConfig config, CancellationToken ct = default)
        {
            await _context.SystemConfigs.AddAsync(config, ct);
        }

        public Task UpdateAsync(SystemConfig config, CancellationToken ct = default)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            var entry = _context.Entry(config);
            if (entry.State == EntityState.Detached)
            {
                _context.SystemConfigs.Update(config);
            }

            // ❌ 不要写这行：config.UpdatedAt = DateTimeOffset.UtcNow;
            // 因为 UpdatedAt 的维护由实体自身的 Update() 方法负责

            return Task.CompletedTask;
        }

        public Task DeleteAsync(SystemConfig config, CancellationToken ct = default)
        {
            _context.SystemConfigs.Remove(config);
            return Task.CompletedTask;
        }

        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            return await _context.SystemConfigs.AnyAsync(x => x.Key == key, ct);
        }
    }
}
