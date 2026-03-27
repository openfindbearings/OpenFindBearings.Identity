using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenIddict.Abstractions;
using Quartz;
using System.Security.Cryptography.X509Certificates;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// 配置 Forwarded Headers 选项
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

    // 清除默认的已知网络限制，允许任何代理（在生产环境中建议限制为 K8s Pod 网段或 Ingress IP）
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure Entity Framework Core
    if (!builder.Environment.IsDevelopment())
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    }
    else
    {
        options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
    }

    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});

// OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
// (like pruning orphaned authorizations/tokens from the database) at regular intervals.
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
});

// Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();

        // Enable Quartz.NET integration.
        options.UseQuartz();
    })

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the token endpoint.
        options.SetTokenEndpointUris("connect/token");
        
        options.AllowClientCredentialsFlow() // Enable the client credentials flow.
               .AllowRefreshTokenFlow();

        // Register the signing and encryption credentials.
        // 证书配置
        if (builder.Environment.IsDevelopment())
        {
            options
                  .AddDevelopmentEncryptionCertificate()
                  .AddDevelopmentSigningCertificate();
        }
        else
        {
            // 生产环境加载真实证书 (从文件、KeyVault 或 K8s Secret)
            var certPassword = builder.Configuration["OpenIddict:certpwd"] ?? "111111";

            var encryptionCert = X509CertificateLoader.LoadPkcs12FromFile("/app/certs/encryption.pfx", certPassword);
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile("/app/certs/signing.pfx", certPassword);

            options.AddEncryptionCertificate(encryptionCert)
                   .AddSigningCertificate(signingCert);

            // 【关键】在生产环境且位于反向代理后时，禁用传输安全强制检查
            // 因为内部通信是 HTTP，但外部是 HTTPS
            options.UseAspNetCore()
                   .DisableTransportSecurityRequirement();
        }

        // 显式禁用访问令牌加密（因为不需要加密）
        options.DisableAccessTokenEncryption();

        // Note: setting a static issuer is mandatory when using mTLS aliases to ensure it not
        // dynamically computed based on the request URI, as this would result in two different
        // issuers being used (one pointing to the mTLS domain and one pointing to the regular one).
        options.SetIssuer(builder.Configuration["OpenIddict:Issuer"] ?? "https://localhost:7201");

        // 配置令牌的有效期
        options.SetAccessTokenLifetime(TimeSpan.FromHours(1))       // A. 访问令牌有效期
               .SetRefreshTokenLifetime(TimeSpan.FromDays(30));     // B. 刷新令牌绝对有效期

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough();
    })

    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// 【必须】在 UseAuthentication 和 UseHttpsRedirection 之前启用转发头中间件
app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();

    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

    if (await scopeManager.FindByNameAsync("api:sync") is null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "api:sync",
            Resources =
                        {
                            "openfindbearings-api"
                        }
        });
    }

    var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    if (await appManager.FindByClientIdAsync("sync-client") == null)
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
}


await app.RunAsync();
