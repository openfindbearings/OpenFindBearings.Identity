using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ValueObjects;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Data
{
    /// <summary>
    /// 种子数据初始化类
    /// </summary>
    public static class SeedData
    {
        /// <summary>
        /// 异步初始化数据库种子数据
        /// </summary>
        /// <param name="provider">服务提供者</param>
        /// <param name="logger">日志记录器</param>
        /// <param name="isDevelopment">是否为开发环境</param>
        public static async Task SeedAsync(IServiceProvider provider, ILogger logger, bool isDevelopment)
        {
            try
            {
                using var scope = provider.CreateScope();
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<OidcUser>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
                var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
                // 改动说明（v2.23.0）：客户端重定向地址改为配置驱动，种子过程不再硬编码占位域名
                var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();

                if (isDevelopment)
                {
                    //await context.Database.EnsureDeletedAsync();
                }

                await context.Database.MigrateAsync();

                await SeedTenantsAsync(context, logger);
                await SeedRolesAsync(roleManager, logger);
                await SeedUsersAsync(userManager, logger);
                await SeedUserRolesAsync(userManager, roleManager, logger);
                await SeedScopesAsync(scopeManager, context, logger);
                await SeedClientsAsync(appManager, context, configuration, logger);

                logger.LogInformation("数据库初始化成功");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "数据库初始化失败");
            }
        }

        #region 租户初始化

        private static async Task SeedTenantsAsync(ApplicationDbContext context, ILogger logger)
        {
            if (await context.Tenants.AnyAsync())
            {
                logger.LogInformation("租户数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化租户数据...");

            var tenants = new[]
            {
                new Tenant
                {
                    Id = TenantConstants.SystemTenantId,
                    Name = TenantConstants.SystemRealm,
                    Description = "Identity 认证中心系统管理",
                    IsEnabled = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Tenant
                {
                    Id = TenantConstants.OpenFindBearingsTenantId,
                    Name = TenantConstants.OpenFindBearingsRealm,
                    Description = "OpenFindBearings 轴承信息管理系统",
                    IsEnabled = true,
                    CreatedAt = DateTime.UtcNow
                }
            };

            context.Tenants.AddRange(tenants);
            await context.SaveChangesAsync();

            logger.LogInformation("租户数据初始化完成，共添加 {Count} 个租户", tenants.Length);
        }

        #endregion

        #region 角色初始化

        private static async Task SeedRolesAsync(RoleManager<IdentityRole<Guid>> roleManager, ILogger logger)
        {
            if (await roleManager.Roles.AnyAsync())
            {
                logger.LogInformation("角色数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化角色数据...");

            var roles = new[]
            {
                new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = "SuperAdmin", NormalizedName = "SUPERADMIN" },
                new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = "Admin", NormalizedName = "ADMIN" },
                new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = "User", NormalizedName = "USER" },
                new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = "TestUser", NormalizedName = "TESTUSER" }
            };

            foreach (var role in roles)
            {
                var result = await roleManager.CreateAsync(role);
                if (!result.Succeeded)
                {
                    logger.LogWarning("创建角色失败: {Name}, Errors: {Errors}",
                        role.Name, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }

            logger.LogInformation("角色数据初始化完成，共添加 {Count} 个角色", roles.Length);
        }

        #endregion

        #region 用户初始化

        private static async Task SeedUsersAsync(UserManager<OidcUser> userManager, ILogger logger)
        {
            if (await userManager.Users.AnyAsync())
            {
                logger.LogInformation("用户数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化用户数据...");

            var usersWithPasswords = new[]
            {
                (User: CreateSystemAdminUser(), Password: "Admin@123456"),
                (User: CreateAdminUser(),        Password: "Admin@123456"),
                (User: CreateTestUser("zhangsan", "张三", "zhangsan@example.com", "+8613800000002"), Password: "User@123456"),
                (User: CreateTestUser("lisi", "李四", "lisi@example.com", "+8613800000003"), Password: "User@123456"),
                (User: CreateTestUser("wangwu", "王五", "wangwu@example.com", null), Password: "User@123456"),
                (User: CreateLockedUser(), Password: "Locked@123456"),
                (User: CreateTestUser("testuser", "测试用户", "test@example.com", "+8613800000005"), Password: "Test@123456")
            };

            foreach (var (user, password) in usersWithPasswords)
            {
                var result = await userManager.CreateAsync(user, password);

                if (!result.Succeeded)
                {
                    logger.LogWarning("创建用户失败: {UserName}, Errors: {Errors}",
                        user.UserName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    continue;
                }

                if (user.UserName == "lockeduser")
                {
                    for (int i = 0; i < 5; i++)
                    {
                        user.RecordFailedLogin(maxAttempts: 5, lockoutMinutes: 15);
                    }
                    await userManager.UpdateAsync(user);
                }
            }

            logger.LogInformation("用户数据初始化完成，共添加 {Count} 个用户", usersWithPasswords.Length);
        }

        private static OidcUser CreateSystemAdminUser()
        {
            var user = OidcUser.Create(
                userName: "admin",
                email: "system@example.com",
                tenantId: TenantConstants.SystemTenantId,
                phoneNumber: "+8613800000099",
                name: "系统管理员",
                givenName: "系统",
                familyName: "管理员");

            SetIdViaReflection(user, TenantConstants.SystemAdminUserId);

            user.UpdateProfile(
                name: "系统管理员",
                givenName: "系统",
                familyName: "管理员",
                nickname: "admin");

            user.SetPreferredUsername("admin");
            user.SetLocale("zh-CN");
            user.SetZoneInfo("Asia/Shanghai");

            user.ConfirmEmail();
            user.ConfirmPhoneNumber();

            return user;
        }

        private static OidcUser CreateAdminUser()
        {
            var user = OidcUser.Create(
                userName: "admin",
                email: "admin@example.com",
                tenantId: TenantConstants.OpenFindBearingsTenantId,
                phoneNumber: "+8613800000001",
                name: "业务管理员",
                givenName: "管理",
                familyName: "员");

            SetIdViaReflection(user, TenantConstants.BusinessAdminUserId);

            user.UpdateProfile(
                name: "业务管理员",
                givenName: "管理",
                familyName: "员",
                nickname: "admin",
                pictureUrl: "https://example.com/admin-avatar.png",
                websiteUrl: "https://example.com");

            user.SetPreferredUsername("admin");
            user.SetProfileUrl("https://example.com/admin-profile");
            user.SetGender("男");
            user.SetBirthdate(new DateOnly(1985, 1, 15));
            user.SetLocale("zh-CN");
            user.SetZoneInfo("Asia/Shanghai");

            user.UpdateAddress(new Address
            {
                Formatted = "中国北京市朝阳区xxx路1号",
                StreetAddress = "xxx路1号",
                Locality = "北京市",
                Region = "北京市",
                PostalCode = "100020",
                Country = "中国"
            });

            user.ConfirmEmail();
            user.ConfirmPhoneNumber();

            return user;
        }

        private static OidcUser CreateTestUser(string username, string name, string email, string? phoneNumber)
        {
            var random = new Random();
            var daysAgo = random.Next(5, 31);
            var lastLoginDaysAgo = random.Next(1, 10);

            string givenName = name.Length > 1 ? name.Substring(1) : name;
            string familyName = name.Length > 0 ? name.Substring(0, 1) : "用";
            string nickname = $"小{familyName}";

            var user = OidcUser.Create(
                userName: username,
                email: email,
                tenantId: TenantConstants.OpenFindBearingsTenantId,
                phoneNumber: phoneNumber,
                name: name,
                givenName: givenName,
                familyName: familyName);

            SetIdViaReflection(user, Guid.NewGuid());

            user.UpdateProfile(
                name: name,
                givenName: givenName,
                familyName: familyName,
                nickname: nickname);

            user.SetPreferredUsername(username);
            user.SetLocale("zh-CN");
            user.SetZoneInfo("Asia/Shanghai");

            user.UpdateAddress(new Address
            {
                Formatted = $"中国某某市测试路{random.Next(1, 100)}号",
                StreetAddress = $"测试路{random.Next(1, 100)}号",
                Locality = "测试市",
                Region = "测试省",
                PostalCode = random.Next(100000, 999999).ToString(),
                Country = "中国"
            });

            SetCreatedAtViaReflection(user, DateTimeOffset.UtcNow.AddDays(-daysAgo));

            user.RecordSuccessfulLogin(
                ip: $"192.168.1.{random.Next(10, 200)}",
                device: GetRandomDevice(),
                location: "中国");

            SetLastLoginAtViaReflection(user, DateTimeOffset.UtcNow.AddDays(-lastLoginDaysAgo));

            user.ConfirmEmail();
            if (phoneNumber != null)
            {
                user.ConfirmPhoneNumber();
            }

            return user;
        }

        private static OidcUser CreateLockedUser()
        {
            var user = OidcUser.Create(
                userName: "lockeduser",
                email: "locked@example.com",
                tenantId: TenantConstants.OpenFindBearingsTenantId,
                phoneNumber: "+8613800000004",
                name: "锁定用户",
                givenName: "锁定",
                familyName: "用户");

            SetIdViaReflection(user, Guid.NewGuid());
            SetCreatedAtViaReflection(user, DateTimeOffset.UtcNow.AddDays(-5));

            user.Disable();

            for (int i = 0; i < 5; i++)
            {
                user.RecordFailedLogin();
            }

            return user;
        }

        private static void SetIdViaReflection(OidcUser user, Guid id)
        {
            var property = typeof(OidcUser).GetProperty("Id");
            if (property != null && property.CanWrite)
            {
                property.SetValue(user, id);
            }
        }

        private static void SetCreatedAtViaReflection(OidcUser user, DateTimeOffset createdAt)
        {
            var field = typeof(OidcUser).GetField("<CreatedAt>k__BackingField",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                field.SetValue(user, createdAt);
            }
        }

        private static void SetLastLoginAtViaReflection(OidcUser user, DateTimeOffset? lastLoginAt)
        {
            var field = typeof(OidcUser).GetField("<LastLoginAt>k__BackingField",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                field.SetValue(user, lastLoginAt);
            }
        }

        private static string GetRandomDevice()
        {
            var devices = new[] { "Web - Chrome", "iOS - Safari", "Android - Chrome", "WeChat" };
            return devices[Random.Shared.Next(devices.Length)];
        }

        #endregion

        #region 用户角色关联初始化

        private static async Task SeedUserRolesAsync(
            UserManager<OidcUser> userManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            ILogger logger)
        {
            logger.LogInformation("开始初始化用户角色关联数据...");

            var systemAdminId = TenantConstants.SystemAdminUserId;
            var businessAdminId = TenantConstants.BusinessAdminUserId;
            var systemAdmin = await userManager.FindByIdAsync(systemAdminId.ToString());
            var businessAdmin = await userManager.FindByIdAsync(businessAdminId.ToString());
            var superAdminRole = await roleManager.FindByNameAsync("SuperAdmin");
            var adminRole = await roleManager.FindByNameAsync("Admin");
            var userRole = await roleManager.FindByNameAsync("User");
            var testUserRole = await roleManager.FindByNameAsync("TestUser");

            if (systemAdmin != null)
            {
                if (superAdminRole != null)
                    await userManager.AddToRoleAsync(systemAdmin, superAdminRole.Name!);
                if (adminRole != null)
                    await userManager.AddToRoleAsync(systemAdmin, adminRole.Name!);
            }

            if (businessAdmin != null)
            {
                if (superAdminRole != null)
                    await userManager.AddToRoleAsync(businessAdmin, superAdminRole.Name!);
                if (adminRole != null)
                    await userManager.AddToRoleAsync(businessAdmin, adminRole.Name!);
            }

            var excludeUsernames = new[] { "testuser" };
            var excludeIds = new[] { systemAdminId, businessAdminId };
            var users = await userManager.Users.ToListAsync();
            foreach (var user in users)
            {
                if (!excludeIds.Contains(user.Id) && !excludeUsernames.Contains(user.UserName!) && userRole != null)
                {
                    await userManager.AddToRoleAsync(user, userRole.Name!);
                }
            }

            var testUser = await userManager.FindByNameAsync("testuser");
            if (testUser != null && testUserRole != null)
            {
                await userManager.AddToRoleAsync(testUser, testUserRole.Name!);
            }

            logger.LogInformation("用户角色关联数据初始化完成");
        }

        #endregion

        #region OpenIddict 客户端和 Scope 初始化

        private static async Task SeedClientsAsync(
            IOpenIddictApplicationManager appManager,
            ApplicationDbContext context,
            IConfiguration configuration,
            ILogger logger)
        {
            var ofbTenantId = TenantConstants.OpenFindBearingsTenantId;

            // 改动说明（v2.23.0）：admin_client 的重定向地址原为硬编码占位域名
            //   https://<your-admin-domain>/callback，尖括号不是合法主机名，new Uri() 抛
            //   UriFormatException 直接中断整个客户端种子（admin_client 与后续幂等补丁全部跳过）。
            //   改为读取 Seed:Clients:Admin:BaseUrl（默认 localhost 开发地址），逐个校验合法性。
            var adminBaseUrl = configuration["Seed:Clients:Admin:BaseUrl"];
            if (string.IsNullOrWhiteSpace(adminBaseUrl))
                adminBaseUrl = "https://localhost:7167";

            var adminRedirectUris = BuildClientUris(logger, "admin_client",
                $"{adminBaseUrl.TrimEnd('/')}/callback",
                "https://localhost:7167/callback");
            var adminPostLogoutUris = BuildClientUris(logger, "admin_client",
                $"{adminBaseUrl.TrimEnd('/')}/signout-callback-oidc",
                "https://localhost:7167/signout-callback-oidc");

            async Task SetTenantIdAsync(string clientId, Guid tenantId)
            {
                var apps = context.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
                var app = await apps.AsTracking().FirstOrDefaultAsync(a => a.ClientId == clientId);
                if (app != null)
                {
                    context.Entry(app).Property("TenantId").CurrentValue = tenantId;
                    await context.SaveChangesAsync();
                }
            }

            async Task CreateIfNotExistsAsync(OpenIddictApplicationDescriptor descriptor, string clientId, Guid tenantId)
            {
                if (await appManager.FindByClientIdAsync(clientId) != null)
                {
                    logger.LogInformation("客户端 [{ClientId}] 已存在，跳过", clientId);
                    return;
                }
                await appManager.CreateAsync(descriptor);
                await SetTenantIdAsync(clientId, tenantId);
                logger.LogInformation("创建客户端 [{ClientId}] 成功", clientId);
            }

            await CreateIfNotExistsAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "sync-client",
                ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
                DisplayName = "同步服务客户端",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api:sync"
                }
            }, "sync-client", ofbTenantId);

            await CreateIfNotExistsAsync(new OpenIddictApplicationDescriptor
            {
                // 改动说明：maui-client 重命名为 mobile-client，与 Taro 移动端项目对齐
                ClientId = "mobile-client",
                ClientType = ClientTypes.Public,
                DisplayName = "移动端 Taro",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    // 改动说明：移动端登出需调 /connect/revocation 吊销 refresh，补 Revocation 端点权限
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Prefixes.GrantType + "sms",
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api:mobile",
                    // 改动说明：password/sms grant 请求 offline_access scope 才签发 refresh_token，
                    // 客户端须具 scp:offline_access 权限（与 Admin 无感续期同源问题），否则移动端
                    // 登录响应无 refresh、冷启动登录态必丢。
                    Permissions.Prefixes.Scope + "offline_access"
                }
            }, "mobile-client", ofbTenantId);

            await CreateIfNotExistsAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                ClientSecret = "web-secret-123",
                DisplayName = "Web 客户端",
                RedirectUris = { new Uri("https://localhost:5002/signin-oidc") },
                PostLogoutRedirectUris = { new Uri("https://localhost:5002/signout-callback-oidc") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.ResponseTypes.Code,
                    Permissions.Prefixes.Scope + "api:web"
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            }, "web-client", ofbTenantId);

            var adminClientDescriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "admin_client",
                ClientSecret = "admin-secret-key",
                ClientType = ClientTypes.Confidential,
                DisplayName = "Admin 后台管理",
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "openid",
                    Permissions.Prefixes.Scope + "api:admin",
                    Permissions.Prefixes.Scope + "api:mobile",
                    // 改动说明：允许 admin_client 请求 offline_access，OpenIddict 授权码流程据此签发 refresh_token，
                    // 使 Admin 能在 access 过期后无感续期（此前缺它 → cookie 无 refresh → 过期即全站 401）。
                    Permissions.Prefixes.Scope + "offline_access"
                }
            };

            // 重定向地址来自配置（见方法开头），逐个加入描述符；非法值已在 BuildClientUris 中过滤
            foreach (var uri in adminRedirectUris)
                adminClientDescriptor.RedirectUris.Add(uri);
            foreach (var uri in adminPostLogoutUris)
                adminClientDescriptor.PostLogoutRedirectUris.Add(uri);

            await CreateIfNotExistsAsync(adminClientDescriptor, "admin_client", ofbTenantId);

            // 幂等补丁：老库 seed 时 mobile-client 尚无 ept:revocation（登出吊销刷新令牌所需）。
            // CreateIfNotExistsAsync 只建不改，故此处对已存在的 mobile-client 追加缺失权限，不覆盖其它字段。
            // 这样发布新镜像即可让"登出吊销 + 改密/禁用/注销即时吊销"链路在既有 prod 库直接生效，免手工 SQL。
            // 改动说明：补丁项追加 scp:offline_access——老库 mobile-client 建时没有该权限，
            // 没有它 password grant 不签 refresh_token，移动端冷启动丢登录态；发布即自愈。
            await EnsureClientPermissionsAsync(context, logger, "mobile-client",
                new[] { Permissions.Endpoints.Revocation, Permissions.Prefixes.Scope + "offline_access" });

            // 幂等补丁：admin_client 需允许 offline_access（签发 refresh_token 的前提）。老库 CreateIfNotExists 只建不改，
            // 故对已存在的 admin_client 追加 scp:offline_access，发布即生效、免手工 SQL。
            await EnsureClientPermissionsAsync(context, logger, "admin_client",
                new[] { Permissions.Prefixes.Scope + "offline_access" });

            // 幂等补丁：把配置里的真实域名补进已存在 admin_client 的重定向列表。
            // CreateIfNotExistsAsync 只建不改，换域名或老库残留占位地址时靠这里补齐，避免登录回跳被拒。
            await EnsureClientRedirectUrisAsync(context, logger, "admin_client",
                adminRedirectUris, adminPostLogoutUris);
        }

        /// <summary>
        /// 将候选地址解析为合法的绝对 http/https URI 列表。
        /// 非法候选（例如未被替换的占位符、空串）只记警告并跳过，绝不抛异常，
        /// 避免单个坏配置导致整个客户端种子中断。
        /// </summary>
        private static List<Uri> BuildClientUris(ILogger logger, string clientId, params string[] candidates)
        {
            var uris = new List<Uri>();
            foreach (var candidate in candidates)
            {
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
                    && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
                {
                    if (!uris.Contains(uri))
                        uris.Add(uri);
                }
                else
                {
                    logger.LogWarning("客户端 {ClientId} 的地址 {Url} 非法，已跳过；请检查 Seed:Clients 配置",
                        clientId, candidate);
                }
            }
            return uris;
        }

        /// <summary>
        /// 幂等补齐指定客户端的重定向地址：仅追加缺失项、不动既有项。
        /// 两个字段均为 EF JSON 文本列，解析失败时记警告并跳过，不影响其它种子步骤。
        /// </summary>
        private static async Task EnsureClientRedirectUrisAsync(
            ApplicationDbContext context,
            ILogger logger,
            string clientId,
            List<Uri> redirectUris,
            List<Uri> postLogoutRedirectUris)
        {
            var apps = context.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            var app = await apps.AsTracking().FirstOrDefaultAsync(a => a.ClientId == clientId);
            if (app == null) return;

            var changed = false;

            if (TryMergeUriJson(app.RedirectUris, redirectUris, out var mergedRedirect))
            {
                app.RedirectUris = mergedRedirect;
                changed = true;
            }

            if (TryMergeUriJson(app.PostLogoutRedirectUris, postLogoutRedirectUris, out var mergedLogout))
            {
                app.PostLogoutRedirectUris = mergedLogout;
                changed = true;
            }

            if (!changed) return;

            await context.SaveChangesAsync();
            logger.LogInformation("幂等补丁：客户端 {ClientId} 补齐重定向地址 {Uris}",
                clientId, string.Join(",", redirectUris.Concat(postLogoutRedirectUris)));
        }

        /// <summary>
        /// 把期望的 URI 合并进 OpenIddict 的 JSON 文本列。
        /// 返回 true 表示确有新增（需要回写）；json 解析失败返回 false 并保留原值。
        /// </summary>
        private static bool TryMergeUriJson(string? json, IEnumerable<Uri> desired, out string merged)
        {
            merged = json ?? "[]";
            List<string> current;
            try
            {
                current = string.IsNullOrWhiteSpace(json)
                    ? new List<string>()
                    : (System.Text.Json.JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>());
            }
            catch
            {
                return false;
            }

            var changed = false;
            foreach (var uri in desired)
            {
                var value = uri.ToString();
                if (!current.Contains(value))
                {
                    current.Add(value);
                    changed = true;
                }
            }

            if (!changed) return false;

            merged = System.Text.Json.JsonSerializer.Serialize(current);
            return true;
        }

        /// <summary>
        /// 幂等补齐指定客户端的权限集：仅追加缺失项、不动既有项。Permissions 为 EF JSON 文本列，直接反序列化后追加。
        /// </summary>
        private static async Task EnsureClientPermissionsAsync(
            ApplicationDbContext context,
            ILogger logger,
            string clientId,
            string[] requiredPermissions)
        {
            var apps = context.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();
            var app = await apps.AsTracking().FirstOrDefaultAsync(a => a.ClientId == clientId);
            if (app == null) return;

            List<string> perms;
            try
            {
                perms = string.IsNullOrEmpty(app.Permissions)
                    ? new List<string>()
                    : (System.Text.Json.JsonSerializer.Deserialize<List<string>>(app.Permissions) ?? new List<string>());
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "解析客户端 {ClientId} Permissions 失败，跳过幂等补丁", clientId);
                return;
            }

            var changed = false;
            foreach (var p in requiredPermissions)
            {
                if (!perms.Contains(p))
                {
                    perms.Add(p);
                    changed = true;
                }
            }

            if (changed)
            {
                app.Permissions = System.Text.Json.JsonSerializer.Serialize(perms);
                await context.SaveChangesAsync();
                logger.LogInformation("幂等补丁：客户端 {ClientId} 追加权限 {Perms}", clientId, string.Join(",", requiredPermissions));
            }
        }

        private static async Task SeedScopesAsync(IOpenIddictScopeManager scopeManager, ApplicationDbContext context, ILogger logger)
        {
            var ofbTenantId = TenantConstants.OpenFindBearingsTenantId;

            async Task CreateScopeWithTenantAsync(string name, string[] resources)
            {
                if (await scopeManager.FindByNameAsync(name) != null)
                {
                    logger.LogInformation("Scope [{Name}] 已存在，跳过", name);
                    return;
                }

                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = name
                };
                foreach (var r in resources)
                {
                    descriptor.Resources.Add(r);
                }
                await scopeManager.CreateAsync(descriptor);

                var scopes = context.Set<OpenIddictEntityFrameworkCoreScope<Guid>>();
                var scope = await scopes.AsTracking().FirstOrDefaultAsync(s => s.Name == name);
                if (scope != null)
                {
                    context.Entry(scope).Property("TenantId").CurrentValue = ofbTenantId;
                    await context.SaveChangesAsync();
                }

                logger.LogInformation("创建 Scope [{Name}] 成功", name);
            }

            // 改动说明（v2.18.0 通用扩展机制）：扩展贡献的资源/scope（如扩展）由 IIdentityExtension 声明，
            //   开源无扩展 = 只建内置 scope；扩展专属 scope 已移出开源
            var extensions = IdentityExtensionLoader.Discover();
            var adminExtra = extensions
                .SelectMany(e => e.AdditionalScopeResources())
                .Where(x => x.ScopeName == "api:admin")
                .Select(x => x.Resource)
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .Distinct()
                .ToArray();

            await CreateScopeWithTenantAsync("api:admin", new[] { ApiResourceConstants.BaseApi }.Concat(adminExtra).ToArray());
            // 改动说明：api:maui 统一重命名为 api:mobile
            await CreateScopeWithTenantAsync("api:mobile", new[] { ApiResourceConstants.BaseApi });
            await CreateScopeWithTenantAsync("api:web", new[] { ApiResourceConstants.BaseApi });

            // 改动说明（v2.18.0 通用扩展机制）：扩展贡献的额外 scope（如外部扩展 scope），开源无扩展 = 无
            foreach (var ext in extensions)
                foreach (var s in ext.AdditionalScopes())
                    await CreateScopeWithTenantAsync(s.Name, s.Resources.ToArray());
        }

        #endregion
    }
}
