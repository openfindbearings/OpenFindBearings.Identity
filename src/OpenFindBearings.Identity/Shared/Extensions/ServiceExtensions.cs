using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenFindBearings.Identity.Data;
using OpenIddict.Abstractions;
using System.Net;

namespace OpenFindBearings.Identity.Shared.Extensions
{
    /// <summary>
    /// 服务注册扩展方法
    /// </summary>
    public static class ServiceExtensions
    {
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

        public static IServiceCollection AddHealthChecksService(this IServiceCollection services)
        {
            services.AddHealthChecks()
                 // 1. 数据库检查（必须）
                 .AddDbContextCheck<ApplicationDbContext>(
                     name: "database",
                     tags: ["db"])

                // 2. OpenIddict 检查（必须）
                .AddCheck<OpenIddictHealthCheck>(
                    name: "openiddict",
                    failureStatus: HealthStatus.Unhealthy)

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
}
