using OpenFindBearings.Identity.Models.DTOs;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    public interface ITenantResolver
    {
        Task<TenantInfo> ResolveAsync();
    }
}
