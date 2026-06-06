using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Client;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 客户端服务接口 - 管理 OAuth2/OIDC 客户端
    /// </summary>
    public interface IClientService
    {
        /// <summary>
        /// 分页获取客户端列表
        /// </summary>
        Task<PaginatedResult<ClientDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default);

        /// <summary>
        /// 根据 ClientId 获取客户端
        /// </summary>
        Task<ClientDto?> GetByClientIdAsync(string clientId, CancellationToken ct = default);

        /// <summary>
        /// 创建新客户端
        /// </summary>
        Task<ServiceResult<ClientDto>> CreateAsync(CreateClientDto request, CancellationToken ct = default);

        /// <summary>
        /// 更新客户端
        /// </summary>
        Task<ServiceResult> UpdateAsync(string clientId, UpdateClientDto request, CancellationToken ct = default);

        /// <summary>
        /// 删除客户端
        /// </summary>
        Task<ServiceResult> DeleteAsync(string clientId, CancellationToken ct = default);

        /// <summary>
        /// 重新生成客户端密钥
        /// </summary>
        Task<ServiceResult<string>> RegenerateSecretAsync(string clientId, CancellationToken ct = default);
    }
}
