using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenFindBearings.Identity.Data;
using OpenIddict.Abstractions;

namespace OpenFindBearings.Identity.Shared.Extensions
{
    /// <summary>
    /// 服务注册扩展方法
    /// </summary>
    public static class ServiceExtensions
    {
        public static IServiceCollection AddCorsService(
            this IServiceCollection services,
            IConfiguration configuration)
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

        public static IServiceCollection AddHealthChecksService(
           this IServiceCollection services,
           IConfiguration configuration)
        {
            services.AddHealthChecks()
                // 1. 数据库检查（必须）
                .AddDbContextCheck<ApplicationDbContext>(
                    name: "database",
                    failureStatus: HealthStatus.Unhealthy)

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
                    failureStatus: HealthStatus.Unhealthy);

            return services;
        }

        public static void MapAllMapHealthChecks(this IEndpointRouteBuilder app)
        {
            app.MapHealthChecks("/health", new HealthCheckOptions
            {
                ResponseWriter = async (context, report) =>
                {
                    context.Response.ContentType = "application/json";
                    var result = new
                    {
                        status = report.Status.ToString(),
                        checks = report.Entries.Select(e => new
                        {
                            name = e.Key,
                            status = e.Value.Status.ToString(),
                            description = e.Value.Description
                        }),
                        duration = report.TotalDuration
                    };
                    await context.Response.WriteAsJsonAsync(result);
                }
            });

            // K8s 风格（简洁响应）
            app.MapHealthChecks("/healthz", new HealthCheckOptions
            {
                Predicate = _ => true,
                ResponseWriter = async (context, report) =>
                {
                    // 修改这里：只有 Unhealthy 才返回 503，Degraded 返回 200
                    var statusCode = report.Status == HealthStatus.Unhealthy ? 503 : 200;
                    context.Response.StatusCode = statusCode;

                    await context.Response.WriteAsync(report.Status.ToString());
                }
            });

            // --- A. 存活探针 (/live) ---
            // 职责：只检查进程是否死锁。
            // 策略：不执行任何注册的检查项 (Predicate = false)。
            app.MapHealthChecks("/live", new HealthCheckOptions
            {
                Predicate = _ => false
            });

            // --- B. 就绪探针 (/ready) ---
            // 职责：检查是否准备好接收流量。
            // 【修复点】：排除 "db" 标签的检查。
            // 原因：在数据库迁移期间，数据库连接可能被占用。如果这里检查数据库，会导致就绪探针失败，
            // 进而导致 K8s 认为服务未就绪甚至重启服务，导致迁移永远无法完成。
            app.MapHealthChecks("/ready", new HealthCheckOptions
            {
                Predicate = check => !check.Tags.Contains("db")
            });
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
