namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 审计日志实体 - 记录所有操作（登录、CRUD、配置变更等）
    /// 用于安全审计和问题追溯
    /// </summary>
    public class AuditLog
    {
        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// 操作人用户 ID
        /// </summary>
        public Guid? UserId { get; set; }

        /// <summary>
        /// 操作人用户名（冗余存储，方便查询）
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// 操作类型：Login、Logout、CreateUser、UpdateClient、DeleteScope 等
        /// </summary>
        public string Action { get; set; } = string.Empty;

        /// <summary>
        /// 资源类型：User、Role、Client、Scope、System
        /// </summary>
        public string? ResourceType { get; set; }

        /// <summary>
        /// 资源 ID（如 UserId、ClientId）
        /// </summary>
        public string? ResourceId { get; set; }

        /// <summary>
        /// 操作详情（JSON 格式，可存储变更前后的数据）
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// 操作状态：Success、Failed
        /// </summary>
        public string? Status { get; set; }

        /// <summary>
        /// 失败原因
        /// </summary>
        public string? FailureReason { get; set; }

        /// <summary>
        /// 客户端 ID
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// IP 地址
        /// </summary>
        public string? IpAddress { get; set; }

        /// <summary>
        /// 用户代理 (User Agent)
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        // ========== 工厂方法 ==========

        /// <summary>
        /// 创建登录日志
        /// </summary>
        public static AuditLog CreateLogin(Guid? userId, string? username, bool success, string? ip,
            string? clientId, string? failureReason = null)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = success ? "Login" : "LoginFailed",
                ResourceType = "User",
                Status = success ? "Success" : "Failed",
                FailureReason = failureReason,
                IpAddress = ip,
                ClientId = clientId,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建登出日志
        /// </summary>
        public static AuditLog CreateLogout(Guid? userId, string? username)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = "Logout",
                ResourceType = "User",
                Status = "Success",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建用户操作日志
        /// </summary>
        public static AuditLog CreateUserAction(Guid? userId, string? username, string action,
            string resourceId, string? details = null, bool success = true, string? failureReason = null)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = action,
                ResourceType = "User",
                ResourceId = resourceId,
                Details = details,
                Status = success ? "Success" : "Failed",
                FailureReason = failureReason,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建客户端操作日志
        /// </summary>
        public static AuditLog CreateClientAction(Guid? userId, string? username, string action,
            string clientId, string? details = null, bool success = true)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = action,
                ResourceType = "Client",
                ResourceId = clientId,
                Details = details,
                Status = success ? "Success" : "Failed",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建角色操作日志
        /// </summary>
        public static AuditLog CreateRoleAction(Guid? userId, string? username, string action,
            string roleId, string? details = null, bool success = true)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = action,
                ResourceType = "Role",
                ResourceId = roleId,
                Details = details,
                Status = success ? "Success" : "Failed",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建 Scope 操作日志
        /// </summary>
        public static AuditLog CreateScopeAction(Guid? userId, string? username, string action,
            string scopeName, string? details = null, bool success = true)
        {
            return new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = action,
                ResourceType = "Scope",
                ResourceId = scopeName,
                Details = details,
                Status = success ? "Success" : "Failed",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        /// <summary>
        /// 创建系统操作日志
        /// </summary>
        public static AuditLog CreateSystemAction(string action, string? details = null,
            bool success = true, string? failureReason = null)
        {
            return new AuditLog
            {
                UserId = null,
                Username = "System",
                Action = action,
                ResourceType = "System",
                Details = details,
                Status = success ? "Success" : "Failed",
                FailureReason = failureReason,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }
    }
}
