using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
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
                await SeedClientsAsync(appManager, context, logger);

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

        private static async Task SeedClientsAsync(IOpenIddictApplicationManager appManager, ApplicationDbContext context, ILogger logger)
        {
            var ofbTenantId = TenantConstants.OpenFindBearingsTenantId;

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
                ClientId = "maui-client",
                ClientType = ClientTypes.Public,
                DisplayName = "MAUI 客户端",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Prefixes.GrantType + "sms",
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api:maui"
                }
            }, "maui-client", ofbTenantId);

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

            await CreateIfNotExistsAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "admin_client",
                ClientSecret = "admin-secret-key",
                ClientType = ClientTypes.Confidential,
                DisplayName = "Admin 后台管理",
                RedirectUris =
                {
                    new Uri("https://admin.515813.xyz/callback"),
                    new Uri("https://localhost:7167/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://admin.515813.xyz/signout-callback-oidc"),
                    new Uri("https://localhost:7167/signout-callback-oidc")
                },
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "openid",
                    Permissions.Prefixes.Scope + "api:admin"
                }
            }, "admin_client", ofbTenantId);
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

            await CreateScopeWithTenantAsync("api:sync", new[] { ApiResourceConstants.BaseApi });
            await CreateScopeWithTenantAsync("api:admin", new[] { ApiResourceConstants.BaseApi, ApiResourceConstants.SyncApi });
            await CreateScopeWithTenantAsync("api:maui", new[] { ApiResourceConstants.BaseApi });
            await CreateScopeWithTenantAsync("api:web", new[] { ApiResourceConstants.BaseApi });
        }

        #endregion
    }
}
