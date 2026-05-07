using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.DTOs;
using OpenFindBearings.Identity.Models.DTOs.Client;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Services
{
    /// <summary>
    /// 客户端服务实现
    /// </summary>
    public class ClientService : IClientService
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IAuditLogRepository _auditLogRepo;

        public ClientService(
            IOpenIddictApplicationManager applicationManager,
            IAuditLogRepository auditLogRepo)
        {
            _applicationManager = applicationManager;
            _auditLogRepo = auditLogRepo;
        }

        /// <inheritdoc/>
        public async Task<PaginatedResult<ClientDto>> GetPagedAsync(int page, int size, string? search = null, CancellationToken ct = default)
        {
            // 收集所有客户端（这种方式适合客户端数量不多的场景）
            var allClients = new List<ClientDto>();

            await foreach (var app in _applicationManager.ListAsync())
            {
                var clientId = await _applicationManager.GetClientIdAsync(app, ct);
                var displayName = await _applicationManager.GetDisplayNameAsync(app, ct);

                if (!string.IsNullOrEmpty(search) && !clientId!.Contains(search) && !displayName!.Contains(search))
                    continue;

                allClients.Add(new ClientDto
                {
                    ClientId = clientId!,
                    DisplayName = displayName!,
                    ClientType = await _applicationManager.GetClientTypeAsync(app, ct)
                });
            }

            var total = allClients.Count;
            var clients = allClients
                .Skip((page - 1) * size)
                .Take(size)
                .ToList();

            return new PaginatedResult<ClientDto>(clients, total, page, size);
        }

        /// <inheritdoc/>
        public async Task<ClientDto?> GetByClientIdAsync(string clientId, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null) return null;

            return new ClientDto
            {
                ClientId = await _applicationManager.GetClientIdAsync(app, ct) ?? string.Empty,
                DisplayName = await _applicationManager.GetDisplayNameAsync(app, ct) ?? string.Empty,
                ClientType = await _applicationManager.GetClientTypeAsync(app, ct) ?? string.Empty
            };
        }

        /// <inheritdoc/>
        public async Task<ServiceResult<ClientDto>> CreateAsync(CreateClientDto request, CancellationToken ct = default)
        {
            var existing = await _applicationManager.FindByClientIdAsync(request.ClientId, ct);
            if (existing != null)
            {
                return ServiceResult<ClientDto>.Failure(new[]
                 {
                    new ServiceError
                    {
                        Code = "ClientAlreadyExists",
                        Description = $"客户端 '{request.ClientId}' 已存在"
                    }
                });
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = request.ClientId,
                ClientSecret = request.ClientSecret,
                DisplayName = request.DisplayName,
                ConsentType = ConsentTypes.Explicit
            };

            // 添加权限
            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);

            // 添加回调地址
            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                descriptor.RedirectUris.Add(new Uri(request.RedirectUri));
            }

            // 添加作用域
            if (request.Scopes != null)
            {
                foreach (var scope in request.Scopes)
                {
                    descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
                }
            }

            await _applicationManager.CreateAsync(descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "CreateClient", request.ClientId, null, true, ct);

            return ServiceResult<ClientDto>.Success(new ClientDto
            {
                ClientId = request.ClientId,
                DisplayName = request.DisplayName
            });
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> UpdateAsync(string clientId, UpdateClientDto request, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null)
            {
                return ServiceResult.Failure(new[]
              {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            // OpenIddict 更新使用 descriptor
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = request.DisplayName
            };

            // 复制现有权限
            var permissions = await _applicationManager.GetPermissionsAsync(app, ct);
            foreach (var permission in permissions)
            {
                descriptor.Permissions.Add(permission);
            }

            await _applicationManager.UpdateAsync(app, descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "UpdateClient", clientId, null, true, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult> DeleteAsync(string clientId, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null)
            {
                return ServiceResult.Failure(new[]
                {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            await _applicationManager.DeleteAsync(app, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "DeleteClient", clientId, null, true, ct);
            return ServiceResult.Success();
        }

        /// <inheritdoc/>
        public async Task<ServiceResult<string>> RegenerateSecretAsync(string clientId, CancellationToken ct = default)
        {
            var app = await _applicationManager.FindByClientIdAsync(clientId, ct);
            if (app == null)
            {
                return ServiceResult<string>.Failure(new[]
                 {
                    new ServiceError
                    {
                        Code = "ClientNotFound",
                        Description = $"客户端 '{clientId}' 不存在"
                    }
                });
            }

            var newSecret = Guid.NewGuid().ToString("N");
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = newSecret,
                DisplayName = await _applicationManager.GetDisplayNameAsync(app, ct)
            };

            await _applicationManager.UpdateAsync(app, descriptor, ct);

            await _auditLogRepo.LogClientActionAsync(null, "System", "RegenerateSecret", clientId, null, true, ct);
            return ServiceResult<string>.Success(newSecret);
        }
    }
}
