using OpenFindBearings.Identity.Areas.Admin.Models.ViewModels.Scope;
using OpenIddict.Abstractions;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 权限范围（Scope）领域模型 - 充血模型，包含业务逻辑
    /// </summary>
    public sealed class Scope
    {
        /// <summary>
        /// 权限范围名称
        /// </summary>
        public string Name { get; private set; }
        
        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; private set; }
        
        /// <summary>
        /// 显示名称
        /// </summary>
        public string? DisplayName { get; private set; }
        
        /// <summary>
        /// 关联的资源列表
        /// </summary>
        public HashSet<string> Resources { get; private set; } = [];
        
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
        private Scope() { }

        /// <summary>
        /// 创建新权限范围
        /// </summary>
        public static Scope Create(string name, string? description = null, string? displayName = null)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Name cannot be empty", nameof(name));

            return new Scope
            {
                Name = name,
                Description = description,
                DisplayName = displayName ?? name,
                IsActive = true
            };
        }

        internal static Scope Create(string name, string? description, string? displayName, HashSet<string>? resources, bool isActive = true)
        {
            return new Scope
            {
                Name = name,
                Description = description,
                DisplayName = displayName,
                Resources = resources ?? [],
                IsActive = isActive
            };
        }

        /// <summary>
        /// 从 OpenIddict Descriptor 创建
        /// </summary>
        public static Scope FromDescriptor(OpenIddictScopeDescriptor descriptor)
        {
            return new Scope
            {
                Name = descriptor.Name ?? string.Empty,
                Description = descriptor.Description,
                DisplayName = descriptor.DisplayName,
                Resources = descriptor.Resources ?? [],
                IsActive = true
            };
        }

        /// <summary>
        /// 转换为 OpenIddict Descriptor
        /// </summary>
        public OpenIddictScopeDescriptor ToDescriptor()
        {
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = Name,
                Description = Description,
                DisplayName = DisplayName
            };

            foreach (var r in Resources) descriptor.Resources.Add(r);

            return descriptor;
        }

        /// <summary>
        /// 是否为标准 OIDC 范围
        /// </summary>
        public bool IsStandardScope => Name is "openid" or "profile" or "email" or "phone" or "address" or "roles";

        /// <summary>
        /// 是否为 API 范围
        /// </summary>
        public bool IsApiScope => Name.StartsWith("api:");

        /// <summary>
        /// 添加资源
        /// </summary>
        public void AddResource(string resource)
        {
            Resources.Add(resource);
        }

        /// <summary>
        /// 移除资源
        /// </summary>
        public void RemoveResource(string resource)
        {
            Resources.Remove(resource);
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
        /// 验证权限范围配置
        /// </summary>
        public (bool IsValid, string? Error) Validate()
        {
            if (string.IsNullOrWhiteSpace(Name))
                return (false, "Name 不能为空");

            if (Name.Contains(' '))
                return (false, "Name 不能包含空格");

            return (true, null);
        }

        /// <summary>
        /// 转换为视图模型
        /// </summary>
        public ScopeViewModel ToViewModel()
        {
            return new ScopeViewModel
            {
                Name = Name,
                Description = Description,
                DisplayName = DisplayName,
                Resources = Resources != null ? [.. Resources] : null
            };
        }
    }
}
