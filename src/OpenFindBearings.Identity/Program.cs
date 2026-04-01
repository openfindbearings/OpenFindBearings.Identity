using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Shared.Extensions;
using Quartz;
using System.Net;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// 配置 Forwarded Headers 选项
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

    //// 清除默认的已知网络限制，允许任何代理（在生产环境中建议限制为 K8s Pod 网段或 Ingress IP）
    //options.KnownIPNetworks.Clear();
    //options.KnownProxies.Clear();

    if (!builder.Environment.IsDevelopment())
    {
        var podCidr = Environment.GetEnvironmentVariable("POD_NETWORK_CIDR");
        if (!string.IsNullOrEmpty(podCidr))
        {
            try
            {
                var parts = podCidr.Split('/');
                if (parts.Length == 2 &&
                    IPAddress.TryParse(parts[0], out var ip) &&
                    int.TryParse(parts[1], out var prefix))
                {
                    options.KnownIPNetworks.Add(new System.Net.IPNetwork(ip, prefix));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to parse CIDR: {ex.Message}");
            }
        }

        // 可选：添加 Service 网络 CIDR
        var serviceCidr = Environment.GetEnvironmentVariable("SERVICE_NETWORK_CIDR");
        if (!string.IsNullOrEmpty(serviceCidr))
        {
            var parts = serviceCidr.Split('/');
            if (parts.Length == 2 &&
                IPAddress.TryParse(parts[0], out var ip) &&
                int.TryParse(parts[1], out var prefix))
            {
                options.KnownIPNetworks.Add(new System.Net.IPNetwork(ip, prefix));
            }
        }
    }
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

// 添加CORS
builder.Services.AddCorsService(builder.Configuration);

// 添加健康检查
builder.Services.AddHealthChecksService();

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("启动 OpenFindBearings Identity");

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

// CORS
app.UseCors("AllowSpecificOrigins");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

// 健康检查
app.MapAllMapHealthChecks();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
// ==========================================
// 执行数据库迁移
// ==========================================
await using(var scope = app.Services.CreateAsyncScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();

        // 使用迁移，但处理异常
        try
        {
            await context.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "迁移失败，尝试重新创建数据库");
            await context.Database.EnsureDeletedAsync();
            await context.Database.MigrateAsync();
        }

        await SeedData.SeedAsync(services);
        logger.LogInformation("数据库初始化成功");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "数据库初始化失败");
    }
}

await app.RunAsync();
