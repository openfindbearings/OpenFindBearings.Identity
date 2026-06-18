using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Services;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;
using Quartz;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Extensions
{
    /// <summary>
    /// 服务注册扩展方法
    /// </summary>
    public static class ServiceExtensions
    {
        /// <summary>
        /// 注册 Identity
        /// </summary>
        public static IServiceCollection AddIdentityService(this IServiceCollection services)
        {
            // 在 AddIdentity 前注册租户感知验证器，防止默认 UserValidator 全局用户名唯一校验
            services.AddScoped<IUserValidator<OidcUser>, TenantAwareUserValidator>();

            services.AddIdentity<OidcUser, IdentityRole<Guid>>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                //options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                //options.Lockout.MaxFailedAccessAttempts = 5;
                //options.Lockout.AllowedForNewUsers = true;
                //options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            return services;
        }
        /// <summary>
        /// 添加 OpenIddict
        /// </summary>
        public static IServiceCollection AddOpenIddictService(this IServiceCollection services, IConfiguration configuration, bool isDevelopment)
        {
            // DbContext
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                // Configure Entity Framework Core
                options.UseNpgsql(configuration.GetConnectionString("DefaultConnection") ?? 
                    throw new InvalidOperationException("Connection string 'ApplicationDbContext' not found."),
                    b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName));

                // Register the entity sets needed by OpenIddict.
                options.UseOpenIddict();
            });

            // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
            // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
            services.AddQuartz(options =>
            {
                options.UseSimpleTypeLoader();
                options.UseInMemoryStore();
            });

            // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
            services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework Core stores and models.
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>()
                           .ReplaceDefaultEntities<Guid>();

                    // Enable Quartz.NET integration.
                    options.UseQuartz();
                })

                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                    // Enable the token endpoint.
                    options.SetTokenEndpointUris("connect/token")
                           .SetUserInfoEndpointUris("connect/userinfo")
                           .SetEndSessionEndpointUris("connect/logout")
                           .SetRevocationEndpointUris("/connect/revocation")
                           .SetAuthorizationEndpointUris("/connect/authorize")
                           ;

                    options.AllowClientCredentialsFlow() // Enable the client credentials flow.
                           .AllowPasswordFlow()
                           //.AllowCustomFlow("sms")
                           //.AllowCustomFlow("wechat")
                           //.AllowCustomFlow("alipay")
                           .AllowAuthorizationCodeFlow()  // 授权码流程（Admin 登录用）
                           .AllowRefreshTokenFlow();

                    // Register the signing and encryption credentials.
                    // 证书配置
                    if (isDevelopment)
                    {
                        options.AddDevelopmentEncryptionCertificate()
                               .AddDevelopmentSigningCertificate();
                        options.UseAspNetCore()
                               .DisableTransportSecurityRequirement();
                    }
                    else
                    {
                        // 生产环境加载真实证书 (从文件、KeyVault 或 K8s Secret)
                        var certPassword = configuration["OpenIddict:certpwd"] ?? "111111";

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
                    options.SetIssuer(configuration["OpenIddict:Issuer"] ?? "https://localhost:7201");

                    // supported scopes.
                    options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.Phone, Scopes.Address);

                    // 配置令牌的有效期
                    options.SetAccessTokenLifetime(TimeSpan.FromMinutes(10))        // A. 访问令牌有效期
                           .SetRefreshTokenLifetime(TimeSpan.FromDays(30));         // B. 刷新令牌绝对有效期

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                    options.UseAspNetCore()
                            .EnableAuthorizationEndpointPassthrough()
                            .EnableTokenEndpointPassthrough()
                            .EnableEndSessionEndpointPassthrough()
                            .EnableStatusCodePagesIntegration();
                })

                // Register the OpenIddict validation components.
                .AddValidation(options =>
                {
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();

                    // Register the ASP.NET Core host.
                    options.UseAspNetCore();
                });

            return services;
        }

        /// <summary>
        /// 添加应用自定义服务
        /// </summary>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddHttpContextAccessor();
            services.AddScoped<ITenantResolver, TenantResolver>();

            // 注册 Services
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IRoleService, RoleService>();
            services.AddScoped<IClientService, ClientService>();
            services.AddScoped<IScopeService, ScopeService>();
            services.AddScoped<IAuditLogService, AuditLogService>();
            services.AddScoped<ISystemConfigService, SystemConfigService>();
            services.AddScoped<ISmsCodeService, SmsCodeService>();
            services.AddScoped<ITenantService, TenantService>();

            // 注册 Repositories
            services.AddScoped<IAuditLogRepository, AuditLogRepository>();
            services.AddScoped<ISmsCodeRepository, SmsCodeRepository>();
            services.AddScoped<ISystemConfigRepository, SystemConfigRepository>();

            return services;
        }

        /// <summary>
        /// 添加跨域
        /// </summary>
        public static IServiceCollection AddCorsService(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigins", policy =>
                {
                    var allowedOrigins = configuration.GetSection("AllowedOrigins").Get<string[]>()
                        ?? ["http://localhost:3000", "https://localhost:7000"];

                    policy.WithOrigins(allowedOrigins)
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials();
                });
            });

            return services;
        }

        /// <summary>
        /// 添加健康检查
        /// </summary>
        public static IServiceCollection AddHealthChecksService(this IServiceCollection services)
        {
            //services.AddHealthChecks();
            services.AddHealthChecks()
                 // 1. 数据库检查（必须）
                 .AddDbContextCheck<ApplicationDbContext>(
                     name: "database",
                     tags: ["startup"])

                // 2. OpenIddict 检查（必须）
                .AddCheck<OpenIddictHealthCheck>(
                     name: "openiddict",
                     failureStatus: HealthStatus.Unhealthy,
                     tags: ["startup"])

                // 3. 内存检查（可选）
                .AddCheck<MemoryHealthCheck>(
                    name: "memory",
                    failureStatus: HealthStatus.Degraded)  // Degraded 表示降级，不是完全不可用

                // 4. 磁盘空间检查（可选）
                .AddCheck<DiskSpaceHealthCheck>(
                    name: "disk",
                    failureStatus: HealthStatus.Degraded);

            return services;
        }

        /// <summary>
        /// 配置转发头
        /// </summary>
        public static IServiceCollection ConfigureForwardedHeaders(this IServiceCollection services, bool isDevelopment)
        {
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                // 所有环境都可以先打开
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor |
                    ForwardedHeaders.XForwardedProto;

                // 但只在非开发环境信任网络
                if (!isDevelopment)
                {
                    AddKnownNetwork(options, "POD_NETWORK_CIDR");
                    AddKnownNetwork(options, "SERVICE_NETWORK_CIDR");
                }
                else
                {
                    // 开发环境：不信任任何代理
                    options.KnownProxies.Clear();
                    options.KnownIPNetworks.Clear();
                }
            });

            return services;
        }

        private static void AddKnownNetwork(ForwardedHeadersOptions options, string envVarName)
        {
            var cidr = Environment.GetEnvironmentVariable(envVarName);
            if (string.IsNullOrEmpty(cidr))
                return;

            try
            {
                var parts = cidr.Split('/');
                if (parts.Length == 2 &&
                    IPAddress.TryParse(parts[0], out var ip) &&
                    int.TryParse(parts[1], out var prefix))
                {
                    options.KnownIPNetworks.Add(new System.Net.IPNetwork(ip, prefix));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to parse CIDR ({envVarName}): {ex.Message}");
            }
        }
    }

    #region 自定义健康检查类
    // ============ 自定义健康检查类 ============

    /// <summary>
    /// OpenIddict 健康检查
    /// </summary>
    public class OpenIddictHealthCheck : IHealthCheck
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<OpenIddictHealthCheck> _logger;

        public OpenIddictHealthCheck(
            IOpenIddictApplicationManager applicationManager,
            ILogger<OpenIddictHealthCheck> logger)
        {
            _applicationManager = applicationManager;
            _logger = logger;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 尝试获取一个已知的客户端来验证 OpenIddict 是否正常
                var client = await _applicationManager.FindByClientIdAsync("sync-client");
                return HealthCheckResult.Healthy();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OpenIddict health check failed");
                return HealthCheckResult.Unhealthy("OpenIddict check failed", ex);
            }
        }
    }

    /// <summary>
    /// 内存健康检查
    /// </summary>
    public class MemoryHealthCheck : IHealthCheck
    {
        private readonly long _thresholdBytes = 512 * 1024 * 1024; // 512MB

        public Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var usedMemory = GC.GetTotalMemory(false);

            if (usedMemory > _thresholdBytes)
            {
                return Task.FromResult(HealthCheckResult.Degraded(
                    $"Memory usage is high: {usedMemory / 1024 / 1024}MB / {_thresholdBytes / 1024 / 1024}MB"));
            }

            return Task.FromResult(HealthCheckResult.Healthy());
        }
    }

    /// <summary>
    /// 磁盘空间健康检查（可选）
    /// </summary>
    public class DiskSpaceHealthCheck : IHealthCheck
    {
        private readonly string _path;
        private readonly long _thresholdBytes; // 最小可用空间

        public DiskSpaceHealthCheck(string path = "/", long thresholdBytes = 1024 * 1024 * 1024) // 默认 1GB
        {
            _path = path;
            _thresholdBytes = thresholdBytes;
        }

        public Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var driveInfo = new DriveInfo(_path);
                var freeSpace = driveInfo.AvailableFreeSpace;

                if (freeSpace < _thresholdBytes)
                {
                    return Task.FromResult(HealthCheckResult.Degraded(
                        $"Low disk space: {freeSpace / 1024 / 1024}MB free, threshold: {_thresholdBytes / 1024 / 1024}MB"));
                }

                return Task.FromResult(HealthCheckResult.Healthy());
            }
            catch (Exception ex)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("Disk space check failed", ex));
            }
        }
    } 
    #endregion
}
