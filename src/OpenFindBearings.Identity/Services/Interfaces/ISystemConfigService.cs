using OpenFindBearings.Identity.Models.DTOs;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 系统配置服务接口 - 管理键值对配置
    /// </summary>
    public interface ISystemConfigService
    {
        /// <summary>
        /// 获取配置值
        /// </summary>
        Task<T?> GetValueAsync<T>(string key, CancellationToken ct = default);

        /// <summary>
        /// 设置配置值
        /// </summary>
        Task SetValueAsync<T>(string key, T value, string? description = null, CancellationToken ct = default);

        /// <summary>
        /// 分页获取所有配置
        /// </summary>
        Task<PaginatedResult<SystemConfigDto>> GetPagedAsync(int page, int size, CancellationToken ct = default);

        /// <summary>
        /// 删除配置
        /// </summary>
        Task<bool> DeleteAsync(string key, CancellationToken ct = default);

        /// <summary>
        /// 检查配置是否存在
        /// </summary>
        Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    }
}
