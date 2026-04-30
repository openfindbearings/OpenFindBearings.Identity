using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories.Interfaces
{
    /// <summary>
    /// 系统配置仓储接口
    /// </summary>
    public interface ISystemConfigRepository
    {
        Task<SystemConfig?> GetByKeyAsync(string key, CancellationToken ct = default);
        Task<IReadOnlyList<SystemConfig>> GetAllAsync(CancellationToken ct = default);
        Task AddAsync(SystemConfig config, CancellationToken ct = default);
        Task UpdateAsync(SystemConfig config, CancellationToken ct = default);
        Task DeleteAsync(SystemConfig config, CancellationToken ct = default);
        Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    }
}
