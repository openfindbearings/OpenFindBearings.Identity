using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Models.DTOs;

namespace OpenFindBearings.Identity.Middleware
{
    public class TenantContextMiddleware
    {
        private readonly RequestDelegate _next;

        public TenantContextMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext)
        {
            var realm = ResolveRealm(context);

            TenantInfo info;
            if (!string.IsNullOrEmpty(realm))
            {
                var tenant = await dbContext.Tenants.AsNoTracking()
                    .FirstOrDefaultAsync(t => t.Name == realm);
                if (tenant != null)
                {
                    info = new TenantInfo
                    {
                        TenantId = tenant.Id,
                        Realm = realm,
                        TenantName = tenant.Name,
                        TenantDescription = tenant.Description
                    };
                }
                else
                {
                    info = new TenantInfo { Realm = realm };
                }
            }
            else
            {
                info = new TenantInfo();
            }

            context.Items["TenantInfo"] = info;
            await _next(context);
        }

        private static string? ResolveRealm(HttpContext context)
        {
            var query = context.Request.Query["realm"].FirstOrDefault();
            if (!string.IsNullOrEmpty(query)) return query;

            if (context.Request.HasFormContentType)
            {
                var form = context.Request.Form["realm"].FirstOrDefault();
                if (!string.IsNullOrEmpty(form)) return form;
            }

            var header = context.Request.Headers["X-Realm"].FirstOrDefault();
            if (!string.IsNullOrEmpty(header)) return header;

            var returnUrl = context.Request.Query["ReturnUrl"].FirstOrDefault();
            if (!string.IsNullOrEmpty(returnUrl))
            {
                var extracted = ExtractRealmFromUrl(returnUrl);
                if (!string.IsNullOrEmpty(extracted)) return extracted;
            }

            return null;
        }

        private static string? ExtractRealmFromUrl(string url)
        {
            var queryStart = url.IndexOf('?');
            if (queryStart < 0) return null;
            var query = url[(queryStart + 1)..];
            foreach (var part in query.Split('&'))
            {
                var eq = part.IndexOf('=');
                if (eq < 0) continue;
                if (part[..eq] == "realm")
                    return Uri.UnescapeDataString(part[(eq + 1)..]);
            }
            return null;
        }
    }

    public static class TenantContextMiddlewareExtensions
    {
        public static IApplicationBuilder UseTenantContext(this IApplicationBuilder app)
        {
            return app.UseMiddleware<TenantContextMiddleware>();
        }
    }
}
