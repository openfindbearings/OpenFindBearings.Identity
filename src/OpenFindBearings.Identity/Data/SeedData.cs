using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.ValueObjects;
using OpenIddict.Abstractions;
using System.Security.Claims;
using System.Security.Cryptography;
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

                // 开发环境：可以删除并重新创建数据库（可选）
                if (isDevelopment)
                {
                    //await context.Database.EnsureDeletedAsync();
                }

                await context.Database.MigrateAsync();

                await SeedRolesAsync(roleManager, logger);
                await SeedUsersAsync(userManager, logger);
                await SeedUserRolesAsync(userManager, roleManager, logger);
                await SeedClientsAsync(appManager, logger);
                await SeedScopesAsync(scopeManager, logger);

                logger.LogInformation("数据库初始化成功");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "数据库初始化失败");
            }
        }

        #region 角色初始化

        /// <summary>
        /// 初始化角色数据
        /// </summary>
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
            new IdentityRole<Guid> { Name = "SuperAdmin" },
            new IdentityRole<Guid> { Name = "Admin" },
            new IdentityRole<Guid> { Name = "User" },
            new IdentityRole<Guid> { Name = "TestUser" }
        };

            foreach (var role in roles)
            {
                await roleManager.CreateAsync(role);
            }

            logger.LogInformation("角色数据初始化完成，共添加 {Count} 个角色", roles.Length);
        }

        #endregion

        #region 用户初始化

        /// <summary>
        /// 初始化用户数据
        /// </summary>
        private static async Task SeedUsersAsync(UserManager<OidcUser> userManager, ILogger logger)
        {
            if (await userManager.Users.AnyAsync())
            {
                logger.LogInformation("用户数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化用户数据...");

            var users = new List<OidcUser>
        {
            CreateAdminUser(),
            CreateTestUser("zhangsan", "张三", "zhangsan@example.com", "+8613800000002"),
            CreateTestUser("lisi", "李四", "lisi@example.com", "+8613800000003"),
            CreateTestUser("wangwu", "王五", "wangwu@example.com", null),
            CreateLockedUser(),
            CreateTestUser("testuser", "测试用户", "test@example.com", "+8613800000005")
        };

            foreach (var user in users)
            {
                var password = user.UserName == "admin" ? "Admin@123456" :
                              user.UserName == "lockeduser" ? "Locked@123456" :
                              user.UserName == "testuser" ? "Test@123456" : "User@123456";
                await userManager.CreateAsync(user, password);
            }

            logger.LogInformation("用户数据初始化完成，共添加 {Count} 个用户", users.Count);
        }

        /// <summary>
        /// 创建管理员用户
        /// </summary>
        private static OidcUser CreateAdminUser()
        {
            return new OidcUser
            {
                Id = Guid.NewGuid(),
                UserName = "admin",
                Email = "admin@example.com",
                PhoneNumber = "+8613800000001",
                EmailConfirmed = true,
                PhoneNumberConfirmed = true,
                Name = "系统管理员",
                GivenName = "管理",
                FamilyName = "员",
                PreferredUsername = "admin",
                IsEnabled = true,
                CreatedAt = DateTimeOffset.UtcNow,
                IsActive = true,
                Address = new Address
                {
                    Formatted = "中国北京市朝阳区xxx路1号",
                    StreetAddress = "xxx路1号",
                    Locality = "北京市",
                    Region = "北京市",
                    PostalCode = "100020",
                    Country = "中国"
                }
            };
        }

        /// <summary>
        /// 创建测试用户
        /// </summary>
        private static OidcUser CreateTestUser(string username, string name, string email, string? phoneNumber)
        {
            var random = new Random();
            var daysAgo = random.Next(5, 31);
            var lastLoginDaysAgo = random.Next(1, 10);

            return new OidcUser
            {
                Id = Guid.NewGuid(),
                UserName = username,
                Email = email,
                PhoneNumber = phoneNumber,
                EmailConfirmed = true,
                PhoneNumberConfirmed = phoneNumber != null,
                Name = name,
                GivenName = name.Length > 1 ? name.Substring(1) : name,
                FamilyName = name.Substring(0, 1),
                Nickname = $"小{name.Substring(0, 1)}",
                PreferredUsername = username,
                IsEnabled = true,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-daysAgo),
                LastLoginAt = DateTimeOffset.UtcNow.AddDays(-lastLoginDaysAgo),
                LastLoginIp = $"192.168.1.{random.Next(10, 200)}",
                LastLoginDevice = GetRandomDevice(),
                IsActive = true,
                Address = new Address
                {
                    Formatted = $"中国某某市测试路{random.Next(1, 100)}号",
                    StreetAddress = $"测试路{random.Next(1, 100)}号",
                    Locality = "测试市",
                    Region = "测试省",
                    PostalCode = random.Next(100000, 999999).ToString(),
                    Country = "中国"
                },
                Locale = "zh-CN",
                ZoneInfo = "Asia/Shanghai"
            };
        }

        /// <summary>
        /// 创建锁定用户
        /// </summary>
        private static OidcUser CreateLockedUser()
        {
            return new OidcUser
            {
                Id = Guid.NewGuid(),
                UserName = "lockeduser",
                Email = "locked@example.com",
                PhoneNumber = "+8613800000004",
                EmailConfirmed = false,
                PhoneNumberConfirmed = false,
                Name = "锁定用户",
                IsEnabled = false,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-5),
                IsActive = true,
                LockoutEnabled = true,
                LockoutEnd = DateTimeOffset.UtcNow.AddDays(1),
                AccessFailedCount = 5
            };
        }

        /// <summary>
        /// 获取随机设备类型
        /// </summary>
        private static string GetRandomDevice()
        {
            var devices = new[] { "Web", "iOS", "Android", "WeChat" };
            return devices[Random.Shared.Next(devices.Length)];
        }

        #endregion

        #region 用户角色关联初始化

        /// <summary>
        /// 初始化用户角色关联
        /// </summary>
        private static async Task SeedUserRolesAsync(
            UserManager<OidcUser> userManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            ILogger logger)
        {
            logger.LogInformation("开始初始化用户角色关联数据...");

            var admin = await userManager.FindByNameAsync("admin");
            var superAdminRole = await roleManager.FindByNameAsync("SuperAdmin");
            var adminRole = await roleManager.FindByNameAsync("Admin");
            var userRole = await roleManager.FindByNameAsync("User");
            var testUserRole = await roleManager.FindByNameAsync("TestUser");

            // Admin 用户分配 SuperAdmin 和 Admin 角色
            if (admin != null)
            {
                if (superAdminRole != null)
                    await userManager.AddToRoleAsync(admin, superAdminRole.Name!);
                if (adminRole != null)
                    await userManager.AddToRoleAsync(admin, adminRole.Name!);
            }

            // 普通用户分配 User 角色
            var users = await userManager.Users.ToListAsync();
            foreach (var user in users)
            {
                if (user.UserName != "admin" && user.UserName != "testuser" && userRole != null)
                {
                    await userManager.AddToRoleAsync(user, userRole.Name!);
                }
            }

            // testuser 分配 TestUser 角色
            var testUser = await userManager.FindByNameAsync("testuser");
            if (testUser != null && testUserRole != null)
            {
                await userManager.AddToRoleAsync(testUser, testUserRole.Name!);
            }

            logger.LogInformation("用户角色关联数据初始化完成");
        }

        #endregion

        #region OpenIddict 客户端和 Scope 初始化

        /// <summary>
        /// 初始化客户端数据
        /// </summary>
        private static async Task SeedClientsAsync(IOpenIddictApplicationManager appManager, ILogger logger)
        {
            // 同步服务客户端
            if (await appManager.FindByClientIdAsync("sync-client") == null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
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
                });
                logger.LogInformation("创建同步服务客户端成功");
            }

            // MAUI 客户端
            if (await appManager.FindByClientIdAsync("maui-client") == null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "maui-client",
                    ClientType = ClientTypes.Public,
                    DisplayName = "MAUI 客户端",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "api:sync"
                    }
                });
                logger.LogInformation("创建 MAUI 客户端成功");
            }

            // Web 客户端（授权码流程）
            if (await appManager.FindByClientIdAsync("web-client") == null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
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
                        Permissions.Prefixes.Scope + "api:sync"
                    }
                });
                logger.LogInformation("创建 Web 客户端成功");
            }
        }

        /// <summary>
        /// 初始化 Scope 数据
        /// </summary>
        private static async Task SeedScopesAsync(IOpenIddictScopeManager scopeManager, ILogger logger)
        {
            var scopes = new[] { "openid", "profile", "email", "phone", "address", "roles" };
            foreach (var scopeName in scopes)
            {
                if (await scopeManager.FindByNameAsync(scopeName) == null)
                {
                    await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                    {
                        Name = scopeName,
                        DisplayName = $"{scopeName} scope",
                        Description = $"Standard OIDC scope: {scopeName}"
                    });
                    logger.LogInformation("创建 Scope [{ScopeName}] 成功", scopeName);
                }
            }
        }

        #endregion
    }
}
