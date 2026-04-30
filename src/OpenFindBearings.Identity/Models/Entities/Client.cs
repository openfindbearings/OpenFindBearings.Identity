using OpenFindBearings.Identity.Areas.Admin.Models.ViewModels.Client;
using OpenIddict.Abstractions;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 客户端（Application）领域模型 - 充血模型，包含业务逻辑
    /// </summary>
    public sealed class Client
    {
        /// <summary>
        /// 客户端ID
        /// </summary>
        public string ClientId { get; private set; }
        
        /// <summary>
        /// 客户端密钥
        /// </summary>
        public string? ClientSecret { get; private set; }
        
        /// <summary>
        /// 显示名称
        /// </summary>
        public string DisplayName { get; private set; }
        
        /// <summary>
        /// 客户端类型 (public/confidential)
        /// </summary>
        public string? ClientType { get; private set; }
        
        /// <summary>
        /// 授权类型
        /// </summary>
        public string? ConsentType { get; private set; }
        
        /// <summary>
        /// 权限列表
        /// </summary>
        public HashSet<string> Permissions { get; private set; } = [];
        
        /// <summary>
        /// 授权回调地址
        /// </summary>
        public HashSet<Uri> RedirectUris { get; private set; } = [];
        
        /// <summary>
        /// 登出回调地址
        /// </summary>
        public HashSet<Uri> PostLogoutRedirectUris { get; private set; } = [];
        
        /// <summary>
        /// 软删除标记
        /// </summary>
        public bool IsActive { get; private set; } = true;
        
        /// <summary>
        /// 删除时间
        /// </summary>
        public DateTimeOffset? DeletedAt { get; private set; }

        /// <summary>
        /// 无参构造函数 - 仅供 EF Core 使用
        /// </summary>
        private Client() { }

        /// <summary>
        /// 创建新客户端
        /// </summary>
        public static Client Create(string clientId, string displayName, string? clientSecret = null, bool isPublic = false)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("ClientId cannot be empty", nameof(clientId));
            if (string.IsNullOrWhiteSpace(displayName))
                throw new ArgumentException("DisplayName cannot be empty", nameof(displayName));

            return new Client
            {
                ClientId = clientId,
                DisplayName = displayName,
                ClientSecret = isPublic ? null : clientSecret,
                ClientType = isPublic ? OpenIddictConstants.ClientTypes.Public : null,
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                IsActive = true
            };
        }

        internal static Client Create(string clientId, string? clientSecret, string displayName, string? clientType,
            string? consentType, HashSet<string>? permissions, HashSet<Uri>? redirectUris, HashSet<Uri>? postLogoutRedirectUris, bool isActive = true)
        {
            return new Client
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                DisplayName = displayName,
                ClientType = clientType,
                ConsentType = consentType,
                Permissions = permissions ?? [],
                RedirectUris = redirectUris ?? [],
                PostLogoutRedirectUris = postLogoutRedirectUris ?? [],
                IsActive = isActive
            };
        }

        /// <summary>
        /// 从 OpenIddict Descriptor 创建
        /// </summary>
        public static Client FromDescriptor(OpenIddictApplicationDescriptor descriptor)
        {
            return new Client
            {
                ClientId = descriptor.ClientId ?? string.Empty,
                ClientSecret = descriptor.ClientSecret,
                DisplayName = descriptor.DisplayName ?? string.Empty,
                ClientType = descriptor.ClientType,
                ConsentType = descriptor.ConsentType,
                Permissions = descriptor.Permissions ?? [],
                RedirectUris = descriptor.RedirectUris ?? [],
                PostLogoutRedirectUris = descriptor.PostLogoutRedirectUris ?? [],
                IsActive = true
            };
        }

        /// <summary>
        /// 转换为 OpenIddict Descriptor
        /// </summary>
        public OpenIddictApplicationDescriptor ToDescriptor()
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                DisplayName = DisplayName,
                ClientType = ClientType,
                ConsentType = ConsentType
            };

            foreach (var p in Permissions) descriptor.Permissions.Add(p);
            foreach (var u in RedirectUris) descriptor.RedirectUris.Add(u);
            foreach (var u in PostLogoutRedirectUris) descriptor.PostLogoutRedirectUris.Add(u);

            return descriptor;
        }

        /// <summary>
        /// 是否为公开客户端
        /// </summary>
        public bool IsPublic => ClientType == OpenIddictConstants.ClientTypes.Public;

        /// <summary>
        /// 添加权限
        /// </summary>
        public void AddPermission(string permission)
        {
            Permissions.Add(permission);
        }

        /// <summary>
        /// 移除权限
        /// </summary>
        public void RemovePermission(string permission)
        {
            Permissions.Remove(permission);
        }

        /// <summary>
        /// 添加授权回调地址
        /// </summary>
        public void AddRedirectUri(Uri uri)
        {
            RedirectUris.Add(uri);
        }

        /// <summary>
        /// 移除授权回调地址
        /// </summary>
        public void RemoveRedirectUri(Uri uri)
        {
            RedirectUris.Remove(uri);
        }

        /// <summary>
        /// 添加登出回调地址
        /// </summary>
        public void AddPostLogoutRedirectUri(Uri uri)
        {
            PostLogoutRedirectUris.Add(uri);
        }

        /// <summary>
        /// 移除登出回调地址
        /// </summary>
        public void RemovePostLogoutRedirectUri(Uri uri)
        {
            PostLogoutRedirectUris.Remove(uri);
        }

        /// <summary>
        /// 软删除
        /// </summary>
        public void SoftDelete()
        {
            IsActive = false;
            DeletedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 恢复软删除
        /// </summary>
        public void Restore()
        {
            IsActive = true;
            DeletedAt = null;
        }

        /// <summary>
        /// 验证客户端配置
        /// </summary>
        public (bool IsValid, string? Error) Validate()
        {
            if (string.IsNullOrWhiteSpace(ClientId))
                return (false, "ClientId 不能为空");
            
            if (string.IsNullOrWhiteSpace(DisplayName))
                return (false, "DisplayName 不能为空");

            if (!IsPublic && string.IsNullOrWhiteSpace(ClientSecret))
                return (false, "机密客户端必须设置 ClientSecret");

            return (true, null);
        }

        /// <summary>
        /// 转换为视图模型
        /// </summary>
        public ClientViewModel ToViewModel()
        {
            return new ClientViewModel
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                DisplayName = DisplayName,
                ClientType = ClientType,
                ConsentType = ConsentType,
                Permissions = [.. Permissions],
                RedirectUris = [.. RedirectUris.Select(u => u.ToString())],
                PostLogoutRedirectUris = [.. PostLogoutRedirectUris.Select(u => u.ToString())]
            };
        }
    }
}
