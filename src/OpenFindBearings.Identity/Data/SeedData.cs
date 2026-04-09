using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Enums;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Data
{
    public static class SeedData
    {
        public static async Task SeedAsync(IServiceProvider provider, ILogger logger, bool isDevelopment)
        {           
            isDevelopment = true; // TODO: 正式发布的时候取消，目前测试期间isDevelopment始终为true

            try
            {
                await using var context = provider.GetRequiredService<ApplicationDbContext>();
                await using var scope = provider.CreateAsyncScope();

                if (isDevelopment)
                {
                    await context.Database.EnsureDeletedAsync();  // 测试期间每次删除，节省每次手动删库的操作
                }

                await context.Database.MigrateAsync();

                await SeedScopesAsync(scope, logger);
                await SeedClientsAsync(scope, logger);
                await SeedUsersAsync(context, logger, "123123", isDevelopment);

                if (isDevelopment)
                {
                    await SeedUserLoginBindingsAsync(context, logger);
                    await SeedUserLoginLogsAsync(context, logger);
                    await SeedSmsVerificationCodesAsync(context, logger);
                }

                logger.LogInformation("数据库初始化成功");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "数据库初始化失败");
            }
        }

        private static async Task SeedClientsAsync(AsyncServiceScope scope, ILogger logger)
        {
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await appManager.FindByClientIdAsync("sync-client") is null)
            {
                try
                {
                    await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "sync-client",
                        ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
                        DisplayName = "sync client application",
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

                    logger.LogInformation("创建同步程序客户端成功");
                }
                catch (Exception ex)
                {
                    logger.LogError($"创建同步程序客户端失败，详细：{ex.Message}");
                }
            }

            if (await appManager.FindByClientIdAsync("maui-client") is null)
            {
                try
                {
                    await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "maui-client",
                        ClientType = ClientTypes.Public,
                        DisplayName = "maui client application",
                        Permissions =
                        {
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.Password,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "api:maui"
                        }
                    });

                    logger.LogInformation("创建Maui客户端成功");
                }
                catch (Exception ex)
                {
                    logger.LogError($"创建Maui客户端失败，详细：{ex.Message}");
                }
            }
        }

        private static async Task SeedScopesAsync(AsyncServiceScope scope, ILogger logger)
        {
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            if (await scopeManager.FindByNameAsync("api:sync") is null)
            {
                try
                {
                    await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                    {
                        Name = "api:sync",
                        Resources =
                        {
                           ApiResourceConstants.BaseApi
                        }
                    });

                    logger.LogInformation("创建Scope[api:sync]成功");
                }
                catch (Exception ex)
                {
                    logger.LogError($"创建Scope[api:sync]失败，详细：{ex.Message}");
                }
            }
        }

        private static async Task SeedUsersAsync(ApplicationDbContext context, ILogger logger, string adminPassword, bool isDevelopment)
        {
            if (await context.Users.AnyAsync())
            {
                logger.LogInformation("用户数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化用户数据...");

            var users = new List<User>
            {
                User.Create(
                    id: Guid.NewGuid(),
                    sub: GenerateSubId(),
                    username: "admin",
                    email: "admin@example.com",
                    phoneNumber: "+8613800000001",
                    passwordHash: HashPassword(adminPassword),
                    emailVerified: true,
                    phoneNumberVerified: true,
                    name: "系统管理员",
                    givenName: "管理",
                    familyName: "员",
                    nickname: null,
                    preferredUsername: "admin",
                    isEnabled: true,
                    createdAt: DateTimeOffset.UtcNow,
                    lastLoginAt: null,
                    lastLoginIp: null,
                    lastLoginDevice: null,
                    customClaims: new Dictionary<string, object>
                    {
                        ["roles"] = new string[] { "SuperAdmin" },
                        ["department"] = "IT",
                        ["level"] = 5
                    },
                    address: new Address
                    {
                        Formatted = "中国北京市朝阳区xxx路1号",
                        StreetAddress = "xxx路1号",
                        Locality = "北京市",
                        Region = "北京市",
                        PostalCode = "100020",
                        Country = "中国"
                    },
                    gender: null,
                    birthdate: null,
                    locale: null,
                    zoneInfo: null
                )
            };

            if (isDevelopment)
            {
                users.AddRange(
                [
                    User.Create(
                        id: Guid.NewGuid(),
                        sub: GenerateSubId(),
                        username: "zhangsan",
                        email: "zhangsan@example.com",
                        phoneNumber: "+8613800000002",
                        passwordHash: HashPassword("User@123456"),
                        emailVerified: true,
                        phoneNumberVerified: true,
                        name: "张三",
                        givenName: "三",
                        familyName: "张",
                        nickname: "小三",
                        preferredUsername: "zhangsan",
                        isEnabled: true,
                        createdAt: DateTimeOffset.UtcNow.AddDays(-30),
                        lastLoginAt: DateTimeOffset.UtcNow.AddDays(-1),
                        lastLoginIp: "192.168.1.100",
                        lastLoginDevice: DeviceTypeConstants.Web,
                        customClaims: new Dictionary<string, object>
                        {
                           ["roles"] = new string[] {  "User"},
                            ["vip_level"] = 1,
                            ["points"] = 1200
                        },
                        address: new Address
                        {
                            Formatted = "中国上海市浦东新区xxx路2号",
                            StreetAddress = "xxx路2号",
                            Locality = "上海市",
                            Region = "上海市",
                            PostalCode = "200120",
                            Country = "中国"
                        },
                        gender: "male",
                        birthdate: "1990-05-15",
                        locale: "zh-CN",
                        zoneInfo: "Asia/Shanghai"
                    ),

                    User.Create(
                        id: Guid.NewGuid(),
                        sub: GenerateSubId(),
                        username: "lisi",
                        email: "lisi@example.com",
                        phoneNumber: "+8613800000003",
                        passwordHash: HashPassword("User@123456"),
                        emailVerified: true,
                        phoneNumberVerified: true,
                        name: "李四",
                        givenName: "四",
                        familyName: "李",
                        nickname: "小四",
                        preferredUsername: "lisi",
                        isEnabled: true,
                        createdAt: DateTimeOffset.UtcNow.AddDays(-20),
                        lastLoginAt: DateTimeOffset.UtcNow.AddDays(-3),
                        lastLoginIp: "192.168.1.101",
                        lastLoginDevice: DeviceTypeConstants.IOS,
                        customClaims: new Dictionary<string, object>
                        {
                            ["roles"] = new string[] {  "User"},
                            ["vip_level"] = 2,
                            ["points"] = 3500
                        },
                        address: new Address
                        {
                            Formatted = "中国广东省深圳市南山区xxx路3号",
                            StreetAddress = "xxx路3号",
                            Locality = "深圳市",
                            Region = "广东省",
                            PostalCode = "518000",
                            Country = "中国"
                        },
                        gender: "female",
                        birthdate: "1992-08-20",
                        locale: "zh-CN",
                        zoneInfo: "Asia/Shanghai"
                    ),

                    User.Create(
                        id: Guid.NewGuid(),
                        sub: GenerateSubId(),
                        username: "wangwu",
                        email: "wangwu@example.com",
                        phoneNumber: null,
                        passwordHash: HashPassword("User@123456"),
                        emailVerified: false,
                        phoneNumberVerified: false,
                        name: "王五",
                        givenName: "五",
                        familyName: "王",
                        nickname: null,
                        preferredUsername: "wangwu",
                        isEnabled: true,
                        createdAt: DateTimeOffset.UtcNow.AddDays(-10),
                        lastLoginAt: DateTimeOffset.UtcNow.AddDays(-2),
                        lastLoginIp: "192.168.1.102",
                        lastLoginDevice: DeviceTypeConstants.Android,
                        customClaims: new Dictionary<string, object>
                        {
                            ["roles"] = new string[] {  "User"},
                            ["vip_level"] = 0,
                            ["points"] = 100
                        },
                        address: null,
                        gender: null,
                        birthdate: null,
                        locale: null,
                        zoneInfo: null
                    ),

                    User.Create(
                        id: Guid.NewGuid(),
                        sub: GenerateSubId(),
                        username: "lockeduser",
                        email: "locked@example.com",
                        phoneNumber: "+8613800000004",
                        passwordHash: HashPassword("User@123456"),
                        emailVerified: false,
                        phoneNumberVerified: false,
                        name: "锁定用户",
                        givenName: null,
                        familyName: null,
                        nickname: null,
                        preferredUsername: "lockeduser",
                        isEnabled: false,
                        createdAt: DateTimeOffset.UtcNow.AddDays(-5),
                        lastLoginAt: null,
                        lastLoginIp: null,
                        lastLoginDevice: null,
                        customClaims: new Dictionary<string, object>
                        {
                            ["roles"] = new string[] { "User"},
                            ["locked_reason"] = "多次密码错误"
                        },
                        address: null,
                        gender: null,
                        birthdate: null,
                        locale: null,
                        zoneInfo: null,
                        accessFailedCount: 5,
                        lockoutEnd: DateTimeOffset.UtcNow.AddDays(1)
                    ),

                    User.Create(
                        id: Guid.NewGuid(),
                        sub: GenerateSubId(),
                        username: "testuser",
                        email: "test@example.com",
                        phoneNumber: "+8613800000005",
                        passwordHash: HashPassword("Test@123456"),
                        emailVerified: true,
                        phoneNumberVerified: true,
                        name: "测试用户",
                        givenName: "测试",
                        familyName: "用户",
                        nickname: null,
                        preferredUsername: "testuser",
                        isEnabled: true,
                        createdAt: DateTimeOffset.UtcNow,
                        lastLoginAt: null,
                        lastLoginIp: null,
                        lastLoginDevice: null,
                        customClaims: new Dictionary<string, object>
                        {
                            ["roles"] = new string[] {  "TestUser"},
                            ["is_test"] = true
                        },
                        address: null,
                        gender: null,
                        birthdate: null,
                        locale: null,
                        zoneInfo: null
                    )
                ]
                );
            }

            await context.Users.AddRangeAsync(users);
            await context.SaveChangesAsync();

            logger.LogInformation("用户数据初始化完成，共添加 {Count} 个用户", users.Count);
        }

        private static async Task SeedUserLoginBindingsAsync(ApplicationDbContext context, ILogger logger)
        {
            if (await context.UserLoginBindings.AnyAsync())
            {
                logger.LogInformation("第三方登录绑定数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化第三方登录绑定数据...");

            var users = await context.Users.ToListAsync();
            var zhangsan = users.FirstOrDefault(u => u.Username == "zhangsan");
            var lisi = users.FirstOrDefault(u => u.Username == "lisi");
            var wangwu = users.FirstOrDefault(u => u.Username == "wangwu");

            if (zhangsan == null || lisi == null || wangwu == null)
            {
                logger.LogWarning("用户数据不存在，跳过第三方登录绑定初始化");
                return;
            }

            var bindings = new List<UserLoginBinding>
            {
                UserLoginBinding.CreateFromSeed(
                    userId: zhangsan.Id,
                    provider: LoginProviders.WeChatMiniProgram,
                    providerUserId: "wechat_openid_zhangsan_12345",
                    unionId: "wechat_unionid_zhangsan",
                    providerNickname: "张三的微信",
                    providerAvatarUrl: "https://example.com/avatars/zhangsan_wechat.jpg",
                    rawData: JsonSerializer.Serialize(new {
                        openid = "wechat_openid_zhangsan_12345",
                        unionid = "wechat_unionid_zhangsan",
                        nickname = "张三的微信",
                        sex = 1,
                        province = "北京",
                        city = "北京",
                        country = "中国"
                    }),
                    bindTime: DateTimeOffset.UtcNow.AddDays(-30),
                    lastUsedTime: DateTimeOffset.UtcNow.AddDays(-1),
                    isUnbound: false,
                    unbindTime: null
                ),

                UserLoginBinding.CreateFromSeed(
                    userId: zhangsan.Id,
                    provider: LoginProviders.Alipay,
                    providerUserId: "alipay_userid_zhangsan_67890",
                    unionId: null,
                    providerNickname: "张三的支付宝",
                    providerAvatarUrl: "https://example.com/avatars/zhangsan_alipay.jpg",
                    rawData: JsonSerializer.Serialize(new
                    {
                        user_id = "alipay_userid_zhangsan_67890",
                        nickname = "张三的支付宝",
                        avatar = "https://example.com/avatars/zhangsan_alipay.jpg"
                    }),
                    bindTime: DateTimeOffset.UtcNow.AddDays(-20),
                    lastUsedTime: DateTimeOffset.UtcNow.AddDays(-5),
                    isUnbound: false,
                    unbindTime: null
                ),

                UserLoginBinding.CreateFromSeed(
                    userId: lisi.Id,
                    provider: LoginProviders.WeChatWeb,
                    providerUserId: "wechat_openid_lisi_11111",
                    unionId: "wechat_unionid_lisi",
                    providerNickname: "李四的微信",
                    providerAvatarUrl: "https://example.com/avatars/lisi_wechat.jpg",
                    rawData: null,
                    bindTime: DateTimeOffset.UtcNow.AddDays(-15),
                    lastUsedTime: DateTimeOffset.UtcNow.AddDays(-10),
                    isUnbound: true,
                    unbindTime: DateTimeOffset.UtcNow.AddDays(-5)
                ),

                UserLoginBinding.CreateFromSeed(
                    userId: wangwu.Id,
                    provider: LoginProviders.PhoneGateway,
                    providerUserId: wangwu.PhoneNumber ?? "+8613800000003",
                    unionId: null,
                    providerNickname: null,
                    providerAvatarUrl: null,
                    rawData: JsonSerializer.Serialize(new
                    {
                        operator_type = "ChinaMobile",
                        phone_number = wangwu.PhoneNumber
                    }),
                    bindTime: DateTimeOffset.UtcNow.AddDays(-8),
                    lastUsedTime: DateTimeOffset.UtcNow.AddDays(-2),
                    isUnbound: false,
                    unbindTime: null
                )
            };

            await context.UserLoginBindings.AddRangeAsync(bindings);
            await context.SaveChangesAsync();

            logger.LogInformation("第三方登录绑定数据初始化完成，共添加 {Count} 条绑定", bindings.Count);
        }

        private static async Task SeedUserLoginLogsAsync(ApplicationDbContext context, ILogger logger)
        {
            if (await context.UserLoginLogs.AnyAsync())
            {
                logger.LogInformation("登录日志数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化登录日志数据...");

            var users = await context.Users.ToListAsync();
            var random = new Random();

            var logs = new List<UserLoginLog>();
            var loginTypes = new[] {
                "password",
                "sms",
                "wechat",
                "alipay",
                "refresh_token",
                "client_credentials"
            };
            var deviceTypes = new[] { DeviceTypeConstants.Web, DeviceTypeConstants.IOS, DeviceTypeConstants.Android, DeviceTypeConstants.WeChat };
            var statuses = new[] { "success", "failed" };

            foreach (var user in users)
            {
                var logCount = random.Next(10, 31);

                for (int i = 0; i < logCount; i++)
                {
                    var daysAgo = random.Next(0, 30);
                    var loginTime = DateTimeOffset.UtcNow.AddDays(-daysAgo);
                    var loginType = loginTypes[random.Next(loginTypes.Length)];
                    var deviceType = deviceTypes[random.Next(deviceTypes.Length)];
                    var status = statuses[random.Next(statuses.Length)];

                    if (user.Username == "admin" && status == "failed")
                        status = "success";

                    if (user.Username == "lockeduser" && status == "success")
                        status = "failed";

                    logs.Add(UserLoginLog.CreateFromSeed(
                        userId: user.Id,
                        loginType: loginType,
                        status: status,
                        failureReason: status == "failed" ? "密码错误" : null,
                        clientId: random.Next(0, 2) == 0 ? "web_app" : "mobile_app",
                        ipAddress: GenerateRandomIp(random),
                        userAgent: GenerateRandomUserAgent(random, deviceType),
                        deviceType: deviceType,
                        deviceId: Guid.NewGuid().ToString(),
                        createdAt: loginTime
                    ));
                }
            }

            var adminUser = users.FirstOrDefault(u => u.Username == "admin");
            if (adminUser != null)
            {
                logs.Add(UserLoginLog.CreateFromSeed(
                    userId: adminUser.Id,
                    loginType: "password",
                    status: "success",
                    failureReason: null,
                    clientId: "admin_panel",
                    ipAddress: "127.0.0.1",
                    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    deviceType: DeviceTypeConstants.Web,
                    deviceId: null,
                    createdAt: DateTimeOffset.UtcNow
                ));
            }

            await context.UserLoginLogs.AddRangeAsync(logs);
            await context.SaveChangesAsync();

            logger.LogInformation("登录日志数据初始化完成，共添加 {Count} 条日志", logs.Count);
        }

        private static async Task SeedSmsVerificationCodesAsync(ApplicationDbContext context, ILogger logger)
        {
            if (await context.SmsVerificationCodes.AnyAsync())
            {
                logger.LogInformation("短信验证码数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化短信验证码数据...");

            var codes = new List<SmsVerificationCode>
            {
                SmsVerificationCode.CreateFromSeed(
                    phoneNumber: "+8613800000002",
                    code: "123456",
                    type: SmsCodeTypeConstants.Login,
                    isUsed: true,
                    usedAt: DateTimeOffset.UtcNow.AddHours(-2),
                    expiresAt: DateTimeOffset.UtcNow.AddHours(-1),
                    createdAt: DateTimeOffset.UtcNow.AddHours(-3),
                    attemptCount: 1
                ),

                SmsVerificationCode.CreateFromSeed(
                    phoneNumber: "+8613800000003",
                    code: "654321",
                    type: SmsCodeTypeConstants.Login,
                    isUsed: false,
                    usedAt: null,
                    expiresAt: DateTimeOffset.UtcNow.AddMinutes(-5),
                    createdAt: DateTimeOffset.UtcNow.AddMinutes(-10),
                    attemptCount: 0
                ),

                SmsVerificationCode.CreateFromSeed(
                    phoneNumber: "+8613800000002",
                    code: "888888",
                    type: SmsCodeTypeConstants.Login,
                    isUsed: false,
                    usedAt: null,
                    expiresAt: DateTimeOffset.UtcNow.AddMinutes(5),
                    createdAt: DateTimeOffset.UtcNow,
                    attemptCount: 0
                ),

                SmsVerificationCode.CreateFromSeed(
                    phoneNumber: "+8613800000004",
                    code: "999999",
                    type: SmsCodeTypeConstants.Bind,
                    isUsed: false,
                    usedAt: null,
                    expiresAt: DateTimeOffset.UtcNow.AddMinutes(10),
                    createdAt: DateTimeOffset.UtcNow,
                    attemptCount: 0
                ),

                SmsVerificationCode.CreateFromSeed(
                    phoneNumber: "+8613800000005",
                    code: "111111",
                    type: SmsCodeTypeConstants.ResetPassword,
                    isUsed: false,
                    usedAt: null,
                    expiresAt: DateTimeOffset.UtcNow.AddMinutes(10),
                    createdAt: DateTimeOffset.UtcNow,
                    attemptCount: 0
                )
            };

            await context.SmsVerificationCodes.AddRangeAsync(codes);
            await context.SaveChangesAsync();

            logger.LogInformation("短信验证码数据初始化完成，共添加 {Count} 条验证码", codes.Count);
        }

        private static string GenerateSubId()
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var random = RandomNumberGenerator.GetInt32(100000, 999999);
            return $"user_{timestamp}_{random}";
        }

        private static string HashPassword(string password)
        {
            return PasswordHasher.CreateHash(password);
        }

        private static string GenerateRandomIp(Random random)
        {
            return $"{random.Next(1, 255)}.{random.Next(0, 255)}.{random.Next(0, 255)}.{random.Next(1, 255)}";
        }

        private static string GenerateRandomUserAgent(Random random, string deviceType)
        {
            return deviceType switch
            {
                DeviceTypeConstants.Web => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                DeviceTypeConstants.IOS => "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
                DeviceTypeConstants.Android => "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 Chrome/120.0.0.0",
                DeviceTypeConstants.WeChat => "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) MicroMessenger/8.0.0",
                _ => "Mozilla/5.0 (Unknown) AppleWebKit/537.36"
            };
        }
    }
}
