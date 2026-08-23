namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 审计日志实体 - 记录所有操作（登录、CRUD、配置变更等）
    /// 用于安全审计和问题追溯
    /// 采用充血模型设计，通过工厂方法创建，属性不可变
    /// </summary>
    public class AuditLog
    {
        /// <summary>
        /// 无参构造函数 - EF Core 需要（private 确保外部不能直接 new）
        /// </summary>
        private AuditLog() { }

        /// <summary>
        /// 私有构造函数 - 由工厂方法调用
        /// </summary>
        private AuditLog(
            Guid? userId,
            string? username,
            string action,
            string? resourceType,
            string? resourceId,
            string? details,
            string? status,
            string? failureReason,
            string? clientId,
            string? ipAddress,
            string? userAgent,
            string? httpMethod = null,
            string? requestPath = null,
            int? statusCode = null,
            long? durationMs = null)
        {
            Id = Guid.NewGuid();
            UserId = userId;
            Username = username;
            Action = action;
            ResourceType = resourceType;
            ResourceId = resourceId;
            Details = details;
            Status = status;
            FailureReason = failureReason;
            ClientId = clientId;
            IpAddress = ipAddress;
            UserAgent = userAgent;
            HttpMethod = httpMethod;
            RequestPath = requestPath;
            StatusCode = statusCode;
            DurationMs = durationMs;
            CreatedAt = DateTimeOffset.UtcNow;
        }

        // ========== 属性（全部 private set） ==========

        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; private set; }

        /// <summary>
        /// 操作人用户 ID
        /// </summary>
        public Guid? UserId { get; private set; }

        /// <summary>
        /// 操作人用户名（冗余存储，方便查询）
        /// </summary>
        public string? Username { get; private set; }

        /// <summary>
        /// 操作类型：Login、Logout、CreateUser、UpdateClient、DeleteScope 等
        /// </summary>
        public string Action { get; private set; } = string.Empty;

        /// <summary>
        /// 资源类型：User、Role、Client、Scope、System
        /// </summary>
        public string? ResourceType { get; private set; }

        /// <summary>
        /// 资源 ID（如 UserId、ClientId）
        /// </summary>
        public string? ResourceId { get; private set; }

        /// <summary>
        /// 操作详情（JSON 格式，可存储变更前后的数据）
        /// </summary>
        public string? Details { get; private set; }

        /// <summary>
        /// 操作状态：Success、Failed
        /// </summary>
        public string? Status { get; private set; }

        /// <summary>
        /// 失败原因
        /// </summary>
        public string? FailureReason { get; private set; }

        /// <summary>
        /// 客户端 ID
        /// </summary>
        public string? ClientId { get; private set; }

        /// <summary>
        /// IP 地址
        /// </summary>
        public string? IpAddress { get; private set; }

        /// <summary>
        /// 用户代理 (User Agent)
        /// </summary>
        public string? UserAgent { get; private set; }

        /// <summary>
        /// HTTP 请求方法
        /// </summary>
        public string? HttpMethod { get; private set; }

        /// <summary>
        /// 请求路径
        /// </summary>
        public string? RequestPath { get; private set; }

        /// <summary>
        /// HTTP 响应状态码
        /// </summary>
        public int? StatusCode { get; private set; }

        /// <summary>
        /// 请求处理耗时（毫秒）
        /// </summary>
        public long? DurationMs { get; private set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }

        // ========== 工厂方法 ==========

        /// <summary>
        /// 创建登录日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="success">是否成功</param>
        /// <param name="ip">IP 地址</param>
        /// <param name="clientId">客户端 ID</param>
        /// <param name="failureReason">失败原因（可选）</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateLogin(
            Guid? userId,
            string? username,
            bool success,
            string? ip,
            string? clientId,
            string? failureReason = null)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: success ? "Login" : "LoginFailed",
                resourceType: "User",
                resourceId: null,
                details: null,
                status: success ? "Success" : "Failed",
                failureReason: failureReason,
                clientId: clientId,
                ipAddress: ip,
                userAgent: null);
        }

        /// <summary>
        /// 创建登出日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateLogout(Guid? userId, string? username)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: "Logout",
                resourceType: "User",
                resourceId: null,
                details: null,
                status: "Success",
                failureReason: null,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建用户操作日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="action">操作类型（如 CreateUser、UpdateUser、DeleteUser）</param>
        /// <param name="resourceId">目标用户 ID</param>
        /// <param name="details">操作详情（JSON 格式）</param>
        /// <param name="success">是否成功</param>
        /// <param name="failureReason">失败原因（可选）</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateUserAction(
            Guid? userId,
            string? username,
            string action,
            string resourceId,
            string? details = null,
            bool success = true,
            string? failureReason = null)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: action,
                resourceType: "User",
                resourceId: resourceId,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: failureReason,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建客户端操作日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="action">操作类型（如 CreateClient、UpdateClient、DeleteClient）</param>
        /// <param name="clientId">目标客户端 ID</param>
        /// <param name="details">操作详情（JSON 格式）</param>
        /// <param name="success">是否成功</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateClientAction(
            Guid? userId,
            string? username,
            string action,
            string clientId,
            string? details = null,
            bool success = true)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: action,
                resourceType: "Client",
                resourceId: clientId,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: null,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建角色操作日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="action">操作类型（如 CreateRole、UpdateRole、DeleteRole）</param>
        /// <param name="roleId">目标角色 ID</param>
        /// <param name="details">操作详情（JSON 格式）</param>
        /// <param name="success">是否成功</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateRoleAction(
            Guid? userId,
            string? username,
            string action,
            string roleId,
            string? details = null,
            bool success = true)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: action,
                resourceType: "Role",
                resourceId: roleId,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: null,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建 Scope 操作日志
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="action">操作类型（如 CreateScope、UpdateScope、DeleteScope）</param>
        /// <param name="scopeName">目标 Scope 名称</param>
        /// <param name="details">操作详情（JSON 格式）</param>
        /// <param name="success">是否成功</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateScopeAction(
            Guid? userId,
            string? username,
            string action,
            string scopeName,
            string? details = null,
            bool success = true)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: action,
                resourceType: "Scope",
                resourceId: scopeName,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: null,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建系统操作日志
        /// </summary>
        /// <param name="action">操作类型（如 SystemStart、SystemStop、DataMigration）</param>
        /// <param name="details">操作详情（JSON 格式）</param>
        /// <param name="success">是否成功</param>
        /// <param name="failureReason">失败原因（可选）</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateSystemAction(
            string action,
            string? details = null,
            bool success = true,
            string? failureReason = null)
        {
            return new AuditLog(
                userId: null,
                username: "System",
                action: action,
                resourceType: "System",
                resourceId: null,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: failureReason,
                clientId: null,
                ipAddress: null,
                userAgent: null);
        }

        /// <summary>
        /// 创建带完整信息的审计日志（扩展方法，用于需要记录 IP 和 UserAgent 的场景）
        /// </summary>
        /// <param name="userId">操作用户 ID</param>
        /// <param name="username">操作用户名</param>
        /// <param name="action">操作类型</param>
        /// <param name="resourceType">资源类型</param>
        /// <param name="resourceId">资源 ID</param>
        /// <param name="details">操作详情</param>
        /// <param name="success">是否成功</param>
        /// <param name="failureReason">失败原因</param>
        /// <param name="clientId">客户端 ID</param>
        /// <param name="ipAddress">IP 地址</param>
        /// <param name="userAgent">用户代理</param>
        /// <returns>审计日志实体</returns>
        public static AuditLog CreateFull(
            Guid? userId,
            string? username,
            string action,
            string? resourceType,
            string? resourceId,
            string? details,
            bool success,
            string? failureReason,
            string? clientId,
            string? ipAddress,
            string? userAgent,
            string? httpMethod = null,
            string? requestPath = null,
            int? statusCode = null,
            long? durationMs = null)
        {
            return new AuditLog(
                userId: userId,
                username: username,
                action: action,
                resourceType: resourceType,
                resourceId: resourceId,
                details: details,
                status: success ? "Success" : "Failed",
                failureReason: failureReason,
                clientId: clientId,
                ipAddress: ipAddress,
                userAgent: userAgent,
                httpMethod: httpMethod,
                requestPath: requestPath,
                statusCode: statusCode,
                durationMs: durationMs);
        }

        // ========== 业务方法 ==========

        /// <summary>
        /// 判断是否为成功操作
        /// </summary>
        public bool IsSuccess() => Status == "Success";

        /// <summary>
        /// 判断是否为失败操作
        /// </summary>
        public bool IsFailed() => Status == "Failed";

        /// <summary>
        /// 判断是否为登录相关操作
        /// </summary>
        public bool IsLoginAction() => Action == "Login" || Action == "LoginFailed";

        /// <summary>
        /// 判断是否为登出操作
        /// </summary>
        public bool IsLogoutAction() => Action == "Logout";

        /// <summary>
        /// 获取操作类型的友好名称
        /// </summary>
        public string GetFriendlyActionName()
        {
            return Action switch
            {
                "Login" => "登录",
                "LoginFailed" => "登录失败",
                "Logout" => "登出",
                "CreateUser" => "创建用户",
                "UpdateUser" => "更新用户",
                "DeleteUser" => "删除用户",
                "CreateClient" => "创建客户端",
                "UpdateClient" => "更新客户端",
                "DeleteClient" => "删除客户端",
                "CreateRole" => "创建角色",
                "UpdateRole" => "更新角色",
                "DeleteRole" => "删除角色",
                "CreateScope" => "创建 Scope",
                "UpdateScope" => "更新 Scope",
                "DeleteScope" => "删除 Scope",
                _ => Action
            };
        }

        /// <summary>
        /// 获取简短描述（用于日志显示）
        /// </summary>
        public string GetShortDescription()
        {
            var actionName = GetFriendlyActionName();
            var userInfo = string.IsNullOrEmpty(Username) ? "系统" : Username;
            var result = IsSuccess() ? "成功" : $"失败: {FailureReason}";

            return $"[{CreatedAt:yyyy-MM-dd HH:mm:ss}] {userInfo} {actionName} {result}";
        }

        /// <summary>
        /// 转换为字符串（用于调试）
        /// </summary>
        public override string ToString()
        {
            return GetShortDescription();
        }
    }
}
