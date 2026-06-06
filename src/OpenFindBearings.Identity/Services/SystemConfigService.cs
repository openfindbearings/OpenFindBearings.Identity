using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.SystemConfig;
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

        public SystemConfigService(ISystemConfigRepository repository)
        {
            _repository = repository;
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
        public async Task<Dictionary<string, object>> GetAllAsDictionaryAsync(CancellationToken ct = default)
        {
            var allConfigs = await _repository.GetAllAsync(ct);
            return allConfigs.ToDictionary(
                x => x.Key,
                x => x.GetValue<object>() ?? (object)string.Empty);
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
                .Select(cfg => cfg.ToDto())
                .ToList();

            return new PaginatedResult<SystemConfigDto>(configs, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteAsync(string key, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null) return false;

            await _repository.DeleteAsync(config, ct);
            await _repository.SaveChangesAsync(ct);
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
        public async Task SetValueAsync<T>(string key, T value, string? description = null, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("配置键不能为空", nameof(key));

            if (value == null)
                throw new ArgumentException("配置值不能为 null", nameof(value));

            var existing = await _repository.GetByKeyAsync(key, ct);
            var jsonValue = System.Text.Json.JsonSerializer.Serialize(value);

            if (existing != null)
            {
                existing.Update(jsonValue, description);
                await _repository.UpdateAsync(existing, ct);
            }
            else
            {
                var config = SystemConfig.Create(key, jsonValue, description);
                await _repository.AddAsync(config, ct);
            }

            await _repository.SaveChangesAsync(ct);
        }

        /// <inheritdoc/>
        public async Task UpdateDescriptionAsync(string key, string? description, CancellationToken ct = default)
        {
            var config = await _repository.GetByKeyAsync(key, ct);
            if (config == null)
                throw new KeyNotFoundException($"配置键 '{key}' 不存在");

            config.UpdateDescription(description);
            await _repository.UpdateAsync(config, ct);
            await _repository.SaveChangesAsync(ct);
        }
    }
}
