using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Data
{
    public static class SeedData
    {     
        public static async Task SeedAsync(IServiceProvider provider)
        {
            await using var scope = provider.CreateAsyncScope();

            // 检查是否已有数据
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            if (await scopeManager.FindByNameAsync("api:sync") is not null)
            {
                return;
            }

            // 创建同步程序的scope
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "api:sync",
                Resources =
                        {
                            "openfindbearings-api"
                        }
            });

            // 创建同步程序客户端
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            if (await appManager.FindByClientIdAsync("sync-client") is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "sync-client",
                    ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
                    DisplayName = "sync client application",
                    Permissions =
                        {
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.ClientCredentials,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "api:sync"
                        }
                });
            }                

            //var envName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            //var isDev = string.IsNullOrWhiteSpace(envName) || envName == "Development"; // 默认视为开发环境
        }
    }
}
