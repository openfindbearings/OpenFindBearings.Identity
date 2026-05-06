using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 系统配置服务实现
    /// </summary>
    public class SystemConfigService : ISystemConfigService
    {
        private readonly ISystemConfigRepository _repository;
        private readonly ApplicationDbContext _context;

        public SystemConfigService(
            ISystemConfigRepository repository,
            ApplicationDbContext context)
        {
            _repository = repository;
            _context = context;
        }

        /// <inheritdoc/>
        public async Task<T?> GetValueAsync<T>(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null)
            {
                return default;
            }

            return config.GetValue<T>();
        }

        /// <inheritdoc/>
        public async Task<string?> GetValueAsync(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            return config?.GetValue();
        }

        /// <inheritdoc/>
        public async Task<T> GetValueOrDefaultAsync<T>(string key, T defaultValue, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null)
            {
                return defaultValue;
            }

            return config.GetValueOrDefault(defaultValue);
        }

        /// <inheritdoc/>
        public async Task SetValueAsync<T>(string key, T value, string? description = null, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("配置键不能为空", nameof(key));

            var existing = await _repository.GetByKeyAsync(key, ct);

            if (existing != null)
            {
                // 使用实体的业务方法更新
                existing.Update(value, description);
                await _repository.UpdateAsync(existing, ct);
            }
            else
            {
                // 使用工厂方法创建
                var config = SystemConfig.Create(key, value, description);
                await _repository.AddAsync(config, ct);
            }

            await _context.SaveChangesAsync(ct);
        }

        /// <inheritdoc/>
        public async Task SetValueAsync(string key, string value, string? description = null, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("配置键不能为空", nameof(key));

            var existing = await _repository.GetByKeyAsync(key, ct);

            if (existing != null)
            {
                // 使用实体的业务方法更新
                existing.Update(value, description);
                await _repository.UpdateAsync(existing, ct);
            }
            else
            {
                // 使用工厂方法创建
                var config = SystemConfig.Create(key, value, description);
                await _repository.AddAsync(config, ct);
            }

            await _context.SaveChangesAsync(ct);
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<SystemConfigDto>> GetPagedAsync(int page, int size, CancellationToken ct = default)
        {
            if (page < 1) page = 1;
            if (size < 1) size = 10;
            if (size > 100) size = 100;

            var allConfigs = await _repository.GetAllAsync(ct);
            var total = allConfigs.Count;

            var configs = allConfigs
                .OrderBy(x => x.Key)
                .Skip((page - 1) * size)
                .Take(size)
                .Select(MapToDto)
                .ToList();

            return new PaginatedResult<SystemConfigDto>(configs, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteAsync(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null) return false;

            await _repository.DeleteAsync(config, ct);
            await _context.SaveChangesAsync(ct);
            return true;
        }

        /// <inheritdoc/>
        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            return await _repository.ExistsAsync(key, ct);
        }

        /// <inheritdoc/>
        public async Task<string?> GetDescriptionAsync(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            return config?.Description;
        }

        /// <inheritdoc/>
        public async Task UpdateDescriptionAsync(string key, string? description, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null)
                throw new KeyNotFoundException($"配置键 '{key}' 不存在");

            // 使用实体的业务方法更新描述
            config.UpdateDescription(description);
            await _repository.UpdateAsync(config, ct);
            await _context.SaveChangesAsync(ct);
        }

        /// <inheritdoc/>
        public async Task<Dictionary<string, object>> GetAllAsDictionaryAsync(CancellationToken ct = default)
        {
            var configs = await _repository.GetAllAsync(ct);
            return configs.ToDictionary(
                x => x.Key,
                x => x.GetValue<object>() ?? (object)string.Empty);
        }

        /// <inheritdoc/>
        public async Task<bool> IsValidJsonAsync(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            return config?.IsValidJson() ?? false;
        }

        /// <summary>
        /// 实体转DTO
        /// </summary>
        private static SystemConfigDto MapToDto(SystemConfig config)
        {
            return new SystemConfigDto
            {
                Key = config.Key,
                Value = config.GetValue(),
                Description = config.Description,
                UpdatedAt = config.UpdatedAt ?? config.CreatedAt
            };
        }
    }
}
