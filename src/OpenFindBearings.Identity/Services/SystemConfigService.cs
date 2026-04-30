using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;
using System.Text.Json;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 系统配置服务实现
    /// 注意：需要在 DbContext 中添加 SystemConfigs DbSet
    /// </summary>
    public class SystemConfigService : ISystemConfigService
    {
        private readonly ApplicationDbContext _context;
        private readonly DbSet<SystemConfig> _dbSet;

        public SystemConfigService(ApplicationDbContext context)
        {
            _context = context;
            _dbSet = context.Set<SystemConfig>();
        }

        /// <inheritdoc/>
        public async Task<T?> GetValueAsync<T>(string key, CancellationToken ct = default)
        {
            var config = await _dbSet.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (config == null || string.IsNullOrEmpty(config.Value))
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(config.Value);
        }

        /// <inheritdoc/>
        public async Task SetValueAsync<T>(string key, T value, string? description = null, CancellationToken ct = default)
        {
            var existing = await _dbSet.FirstOrDefaultAsync(x => x.Key == key, ct);
            var jsonValue = JsonSerializer.Serialize(value);

            if (existing != null)
            {
                existing.Value = jsonValue;
                existing.Description = description ?? existing.Description;
                existing.UpdatedAt = DateTimeOffset.UtcNow;
                _dbSet.Update(existing);
            }
            else
            {
                var config = new SystemConfig
                {
                    Key = key,
                    Value = jsonValue,
                    Description = description,
                    CreatedAt = DateTimeOffset.UtcNow
                };
                await _dbSet.AddAsync(config, ct);
            }

            await _context.SaveChangesAsync(ct);
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<SystemConfigDto>> GetPagedAsync(int page, int size, CancellationToken ct = default)
        {
            var total = await _dbSet.CountAsync(ct);
            var configs = await _dbSet
                .OrderBy(x => x.Key)
                .Skip((page - 1) * size)
                .Take(size)
                .ToListAsync(ct);

            return new PaginatedResult<SystemConfigDto>(configs.Select(MapToDto).ToList(), total, page, size);
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteAsync(string key, CancellationToken ct = default)
        {
            var config = await _dbSet.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (config == null) return false;

            _dbSet.Remove(config);
            await _context.SaveChangesAsync(ct);
            return true;
        }

        /// <inheritdoc/>
        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            return await _dbSet.AnyAsync(x => x.Key == key, ct);
        }

        /// <summary>
        /// 实体转DTO
        /// </summary>
        private static SystemConfigDto MapToDto(SystemConfig config)
        {
            return new SystemConfigDto
            {
                Key = config.Key,
                Value = config.Value,
                Description = config.Description,
                UpdatedAt = config.UpdatedAt ?? config.CreatedAt
            };
        }
    }
}
