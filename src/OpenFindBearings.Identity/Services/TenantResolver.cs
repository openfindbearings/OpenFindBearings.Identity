using OpenFindBearings.Identity.Models.DTOs;

namespace OpenFindBearings.Identity.Services.Interfaces
{
    public class TenantResolver : ITenantResolver
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public TenantResolver(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public Task<TenantInfo> ResolveAsync()
        {
            var httpContext = _httpContextAccessor.HttpContext
                ?? throw new InvalidOperationException("HttpContext is not available");

            if (httpContext.Items["TenantInfo"] is TenantInfo cached)
                return Task.FromResult(cached);

            return Task.FromResult(new TenantInfo());
        }
    }
}
