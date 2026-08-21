using System.Diagnostics;
using System.Text;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Middleware
{
    /// <summary>
    /// 审计日志中间件 - 统一记录所有写操作（POST/PUT/PATCH/DELETE）
    /// 跳过健康检查与 OAuth 协议端点（/connect/*），避免噪声日志
    /// </summary>
    public class AuditLogMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<AuditLogMiddleware> _logger;

        public AuditLogMiddleware(RequestDelegate next, ILogger<AuditLogMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, IAuditLogRepository repository, ApplicationDbContext dbContext)
        {
            var method = context.Request.Method;
            var path = context.Request.Path.Value ?? "";

            if (ShouldSkip(method, path))
            {
                await _next(context);
                return;
            }

            string? requestBody = null;
            if (context.Request.ContentType != null &&
                context.Request.ContentType.Contains("application/json"))
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                requestBody = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;
                if (!string.IsNullOrEmpty(requestBody) && requestBody.Length > 2000)
                    requestBody = requestBody[..2000] + "...(截断)";
            }

            var sw = Stopwatch.StartNew();
            try
            {
                await _next(context);
            }
            finally
            {
                sw.Stop();
                try
                {
                    var success = context.Response.StatusCode < 400;
                    var statusCode = context.Response.StatusCode;

                    var log = AuditLog.CreateFull(
                        userId: Guid.TryParse(context.User.FindFirst("sub")?.Value, out var uid) ? uid : null,
                        username: context.User.FindFirst("name")?.Value
                                   ?? context.User.FindFirst("preferred_username")?.Value,
                        action: MapAction(method, path, statusCode),
                        resourceType: ExtractEntityType(path),
                        resourceId: ExtractEntityId(path),
                        details: requestBody,
                        success: success,
                        failureReason: success ? null : $"HTTP {statusCode}",
                        clientId: context.User.FindFirst("client_id")?.Value,
                        ipAddress: context.Connection.RemoteIpAddress?.ToString(),
                        userAgent: context.Request.Headers.UserAgent.ToString(),
                        httpMethod: method,
                        requestPath: path,
                        statusCode: statusCode,
                        durationMs: sw.ElapsedMilliseconds);

                    await repository.AddAsync(log, context.RequestAborted);
                    await dbContext.SaveChangesAsync(context.RequestAborted);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "写入审计日志失败: {Method} {Path}", method, path);
                }
            }
        }

        private static bool ShouldSkip(string method, string path)
        {
            if (method == "GET" || method == "HEAD" || method == "OPTIONS")
                return true;
            if (path.Contains("/health", StringComparison.OrdinalIgnoreCase))
                return true;
            if (path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }

        private static string? ExtractEntityType(string path)
        {
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < segments.Length; i++)
                if (segments[i].Equals("api", StringComparison.OrdinalIgnoreCase) && i + 1 < segments.Length)
                    return segments[i + 1];
            if (segments.Length > 0 && segments[0].Equals("Account", StringComparison.OrdinalIgnoreCase))
                return "Account";
            return null;
        }

        private static string? ExtractEntityId(string path)
        {
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            foreach (var s in segments)
                if (Guid.TryParse(s, out _))
                    return s;
            return null;
        }

        private static string MapAction(string method, string path, int statusCode)
        {
            if (path.Equals("/Account/Login", StringComparison.OrdinalIgnoreCase))
                return statusCode == 302 ? "Login" : "LoginFailed";
            if (path.Equals("/Account/Logout", StringComparison.OrdinalIgnoreCase))
                return "Logout";
            return method switch
            {
                "POST" => "Create",
                "PUT" or "PATCH" => "Update",
                "DELETE" => "Delete",
                _ => method
            };
        }
    }
}