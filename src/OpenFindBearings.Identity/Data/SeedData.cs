using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Data.Entities;
using OpenFindBearings.Identity.Data.Enums;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Data
{
    public static class SeedData
    {
        public static async Task SeedAsync(IServiceProvider provider, ILogger logger, bool isDevelopment)
        {
            try
            {
                await using var context = provider.GetRequiredService<ApplicationDbContext>();
                await using var scope = provider.CreateAsyncScope();

                // 使用迁移
                await context.Database.MigrateAsync();

                // 按顺序初始化，避免外键依赖问题
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

        #region 填充数据方法

        /// <summary>
        /// 初始化客户端数据
        /// </summary>
        private static async Task SeedClientsAsync(AsyncServiceScope scope, ILogger logger)
        {
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            // 创建同步程序客户端
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

            // 创建Maui客户端
            if (await appManager.FindByClientIdAsync("maui-client") is null)
            {
                try
                {
                    await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "maui-client",
                        //ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
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

        /// <summary>
        /// 初始化Scope数据
        /// </summary>
        private static async Task SeedScopesAsync(AsyncServiceScope scope, ILogger logger)
        {
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            if (await scopeManager.FindByNameAsync("api:sync") is null)
            {
                try
                {
                    // 创建同步程序的scope
                    await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                    {
                        Name = "api:sync",
                        Resources =
                        {
                            "openfindbearings-api"
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

        /// <summary>
        /// 初始化用户数据
        /// </summary>
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
                new User
                {
                    Sub = GenerateSubId(),
                    Username = "admin",
                    PasswordHash = HashPassword(adminPassword),
                    Email = "admin@example.com",
                    EmailVerified = true,
                    PhoneNumber = "+8613800000001",
                    PhoneNumberVerified = true,
                    Name = "系统管理员",
                    GivenName = "管理",
                    FamilyName = "员",
                    PreferredUsername = "admin",
                    IsEnabled = true,
                    CreatedAt = DateTimeOffset.UtcNow,
                    LastLoginAt = null,
                    CustomClaims = new Dictionary<string, object>
                    {
                        ["role"] = "SuperAdmin",
                        ["department"] = "IT",
                        ["level"] = 5
                    },
                    Address = new Address
                    {
                        Formatted = "中国北京市朝阳区xxx路1号",
                        StreetAddress = "xxx路1号",
                        Locality = "北京市",
                        Region = "北京市",
                        PostalCode = "100020",
                        Country = "中国"
                    }
                }
            };

            if (isDevelopment)
            {
                users.AddRange(
                [
                    // 2. 普通用户 - 张三
                    new User
                    {
                        Sub = GenerateSubId(),
                        Username = "zhangsan",
                        PasswordHash = HashPassword("User@123456"),
                        Email = "zhangsan@example.com",
                        EmailVerified = true,
                        PhoneNumber = "+8613800000002",
                        PhoneNumberVerified = true,
                        Name = "张三",
                        GivenName = "三",
                        FamilyName = "张",
                        Nickname = "小三",
                        PreferredUsername = "zhangsan",
                        Gender = "male",
                        Birthdate = "1990-05-15",
                        Locale = "zh-CN",
                        ZoneInfo = "Asia/Shanghai",
                        IsEnabled = true,
                        CreatedAt = DateTimeOffset.UtcNow.AddDays(-30),
                        LastLoginAt = DateTimeOffset.UtcNow.AddDays(-1),
                        LastLoginIp = "192.168.1.100",
                        LastLoginDevice = DeviceTypes.Web,
                        CustomClaims = new Dictionary<string, object>
                        {
                            ["role"] = "User",
                            ["vip_level"] = 1,
                            ["points"] = 1200
                        },
                        Address = new Address
                        {
                            Formatted = "中国上海市浦东新区xxx路2号",
                            StreetAddress = "xxx路2号",
                            Locality = "上海市",
                            Region = "上海市",
                            PostalCode = "200120",
                            Country = "中国"
                        }
                    },

                    // 3. 普通用户 - 李四
                    new User
                    {
                        Sub = GenerateSubId(),
                        Username = "lisi",
                        PasswordHash = HashPassword("User@123456"),
                        Email = "lisi@example.com",
                        EmailVerified = true,
                        PhoneNumber = "+8613800000003",
                        PhoneNumberVerified = true,
                        Name = "李四",
                        GivenName = "四",
                        FamilyName = "李",
                        Nickname = "小四",
                        PreferredUsername = "lisi",
                        Gender = "female",
                        Birthdate = "1992-08-20",
                        Locale = "zh-CN",
                        ZoneInfo = "Asia/Shanghai",
                        IsEnabled = true,
                        CreatedAt = DateTimeOffset.UtcNow.AddDays(-20),
                        LastLoginAt = DateTimeOffset.UtcNow.AddDays(-3),
                        LastLoginIp = "192.168.1.101",
                        LastLoginDevice = DeviceTypes.IOS,
                        CustomClaims = new Dictionary<string, object>
                        {
                            ["role"] = "User",
                            ["vip_level"] = 2,
                            ["points"] = 3500
                        },
                        Address = new Address
                        {
                            Formatted = "中国广东省深圳市南山区xxx路3号",
                            StreetAddress = "xxx路3号",
                            Locality = "深圳市",
                            Region = "广东省",
                            PostalCode = "518000",
                            Country = "中国"
                        }
                    },

                    // 4. 普通用户 - 王五（只有邮箱，没有手机号）
                    new User
                    {
                        Sub = GenerateSubId(),
                        Username = "wangwu",
                        PasswordHash = HashPassword("User@123456"),
                        Email = "wangwu@example.com",
                        EmailVerified = false,  // 邮箱未验证
                        PhoneNumber = null,
                        PhoneNumberVerified = false,
                        Name = "王五",
                        GivenName = "五",
                        FamilyName = "王",
                        PreferredUsername = "wangwu",
                        IsEnabled = true,
                        CreatedAt = DateTimeOffset.UtcNow.AddDays(-10),
                        LastLoginAt = DateTimeOffset.UtcNow.AddDays(-2),
                        LastLoginIp = "192.168.1.102",
                        LastLoginDevice = DeviceTypes.Android,
                        CustomClaims = new Dictionary<string, object>
                        {
                            ["role"] = "User",
                            ["vip_level"] = 0,
                            ["points"] = 100
                        }
                    },

                    // 5. 禁用账户示例
                    new User
                    {
                        Sub = GenerateSubId(),
                        Username = "lockeduser",
                        PasswordHash = HashPassword("User@123456"),
                        Email = "locked@example.com",
                        EmailVerified = false,
                        PhoneNumber = "+8613800000004",
                        PhoneNumberVerified = false,
                        Name = "锁定用户",
                        PreferredUsername = "lockeduser",
                        IsEnabled = false,  // 账户被禁用
                        CreatedAt = DateTimeOffset.UtcNow.AddDays(-5),
                        LastLoginAt = null,
                        AccessFailedCount = 5,
                        LockoutEnd = DateTimeOffset.UtcNow.AddDays(1),  // 锁定到明天
                        CustomClaims = new Dictionary<string, object>
                        {
                            ["role"] = "User",
                            ["locked_reason"] = "多次密码错误"
                        }
                    },

                    // 6. 测试用户 - 用于开发测试
                    new User
                    {
                        Sub = GenerateSubId(),
                        Username = "testuser",
                        PasswordHash = HashPassword("Test@123456"),
                        Email = "test@example.com",
                        EmailVerified = true,
                        PhoneNumber = "+8613800000005",
                        PhoneNumberVerified = true,
                        Name = "测试用户",
                        GivenName = "测试",
                        FamilyName = "用户",
                        PreferredUsername = "testuser",
                        IsEnabled = true,
                        CreatedAt = DateTimeOffset.UtcNow,
                        LastLoginAt = null,
                        CustomClaims = new Dictionary<string, object>
                        {
                            ["role"] = "TestUser",
                            ["is_test"] = true
                        }
                    }
                ]
                );
            }

            await context.Users.AddRangeAsync(users);
            await context.SaveChangesAsync();

            logger.LogInformation("用户数据初始化完成，共添加 {Count} 个用户", users.Count);
        }

        /// <summary>
        /// 初始化第三方登录绑定数据
        /// </summary>
        private static async Task SeedUserLoginBindingsAsync(ApplicationDbContext context, ILogger logger)
        {
            if (await context.UserLoginBindings.AnyAsync())
            {
                logger.LogInformation("第三方登录绑定数据已存在，跳过初始化");
                return;
            }

            logger.LogInformation("开始初始化第三方登录绑定数据...");

            // 获取已创建的用户
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
                // 张三绑定了微信
                new UserLoginBinding
                {
                    UserId = zhangsan.Sub,
                    Provider = LoginProvider.WeChatMiniProgram,
                    ProviderUserId = "wechat_openid_zhangsan_12345",
                    UnionId = "wechat_unionid_zhangsan",
                    ProviderNickname = "张三的微信",
                    ProviderAvatarUrl = "https://example.com/avatars/zhangsan_wechat.jpg",
                    RawData = JsonSerializer.Serialize(new {
                        openid = "wechat_openid_zhangsan_12345",
                        unionid = "wechat_unionid_zhangsan",
                        nickname = "张三的微信",
                        sex = 1,
                        province = "北京",
                        city = "北京",
                        country = "中国"
                    }),
                    BindTime = DateTimeOffset.UtcNow.AddDays(-30),
                    LastUsedTime = DateTimeOffset.UtcNow.AddDays(-1),
                    IsUnbound = false
                },

                // 张三绑定了支付宝
                new UserLoginBinding
                {
                    UserId = zhangsan.Sub,
                    Provider = LoginProvider.Alipay,
                    ProviderUserId = "alipay_userid_zhangsan_67890",
                    ProviderNickname = "张三的支付宝",
                    ProviderAvatarUrl = "https://example.com/avatars/zhangsan_alipay.jpg",
                    RawData = JsonSerializer.Serialize(new
                    {
                        user_id = "alipay_userid_zhangsan_67890",
                        nickname = "张三的支付宝",
                        avatar = "https://example.com/avatars/zhangsan_alipay.jpg"
                    }),
                    BindTime = DateTimeOffset.UtcNow.AddDays(-20),
                    LastUsedTime = DateTimeOffset.UtcNow.AddDays(-5),
                    IsUnbound = false
                },

                // 李四绑定了微信（已解绑）
                new UserLoginBinding
                {
                    UserId = lisi.Sub,
                    Provider = LoginProvider.WeChatWeb,
                    ProviderUserId = "wechat_openid_lisi_11111",
                    UnionId = "wechat_unionid_lisi",
                    ProviderNickname = "李四的微信",
                    ProviderAvatarUrl = "https://example.com/avatars/lisi_wechat.jpg",
                    BindTime = DateTimeOffset.UtcNow.AddDays(-15),
                    LastUsedTime = DateTimeOffset.UtcNow.AddDays(-10),
                    IsUnbound = true,
                    UnbindTime = DateTimeOffset.UtcNow.AddDays(-5)
                },

                // 王五绑定了本机一键登录
                new UserLoginBinding
                {
                    UserId = wangwu.Sub,
                    Provider = LoginProvider.PhoneGateway,
                    ProviderUserId = wangwu.PhoneNumber ?? "+8613800000003",
                    RawData = JsonSerializer.Serialize(new
                    {
                        operator_type = "ChinaMobile",
                        phone_number = wangwu.PhoneNumber
                    }),
                    BindTime = DateTimeOffset.UtcNow.AddDays(-8),
                    LastUsedTime = DateTimeOffset.UtcNow.AddDays(-2),
                    IsUnbound = false
                }
            };

            await context.UserLoginBindings.AddRangeAsync(bindings);
            await context.SaveChangesAsync();

            logger.LogInformation("第三方登录绑定数据初始化完成，共添加 {Count} 条绑定", bindings.Count);
        }

        /// <summary>
        /// 初始化登录日志数据
        /// </summary>
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
                LoginTypes.Password,
                LoginTypes.Sms,
                LoginTypes.WeChat,
                LoginTypes.Alipay,
                LoginTypes.RefreshToken,
                LoginTypes.ClientCredentials
            };
            var deviceTypes = new[] { DeviceTypes.Web, DeviceTypes.IOS, DeviceTypes.Android, DeviceTypes.WeChat };
            var statuses = new[] { "success", "failed" };

            // 为每个用户生成最近30天的登录日志
            foreach (var user in users)
            {
                // 随机生成10-30条日志
                var logCount = random.Next(10, 31);

                for (int i = 0; i < logCount; i++)
                {
                    var daysAgo = random.Next(0, 30);
                    var loginTime = DateTimeOffset.UtcNow.AddDays(-daysAgo);
                    var loginType = loginTypes[random.Next(loginTypes.Length)];
                    var deviceType = deviceTypes[random.Next(deviceTypes.Length)];
                    var status = statuses[random.Next(statuses.Length)];

                    // 如果是管理员，增加一些成功登录记录
                    if (user.Username == "admin" && status == "failed")
                        status = "success";

                    // 如果是锁定用户，增加失败记录
                    if (user.Username == "lockeduser" && status == "success")
                        status = "failed";

                    logs.Add(new UserLoginLog
                    {
                        UserId = user.Sub,
                        LoginType = loginType,
                        Status = status,
                        FailureReason = status == "failed" ? "密码错误" : null,
                        ClientId = random.Next(0, 2) == 0 ? "web_app" : "mobile_app",
                        IpAddress = GenerateRandomIp(random),
                        UserAgent = GenerateRandomUserAgent(random, deviceType),
                        DeviceType = deviceType,
                        DeviceId = Guid.NewGuid().ToString(),
                        CreatedAt = loginTime
                    });
                }
            }

            // 添加一些特殊的测试日志
            var adminUser = users.FirstOrDefault(u => u.Username == "admin");
            if (adminUser != null)
            {
                // 管理员今天的登录
                logs.Add(new UserLoginLog
                {
                    UserId = adminUser.Sub,
                    LoginType = LoginTypes.Password,
                    Status = "success",
                    ClientId = "admin_panel",
                    IpAddress = "127.0.0.1",
                    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    DeviceType = DeviceTypes.Web,
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }

            await context.UserLoginLogs.AddRangeAsync(logs);
            await context.SaveChangesAsync();

            logger.LogInformation("登录日志数据初始化完成，共添加 {Count} 条日志", logs.Count);
        }

        /// <summary>
        /// 初始化短信验证码数据
        /// </summary>
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
                // 已使用且过期的验证码示例
                new SmsVerificationCode
                {
                    PhoneNumber = "+8613800000002",
                    Code = "123456",
                    Type = SmsCodeTypes.Login,
                    IsUsed = true,
                    UsedAt = DateTimeOffset.UtcNow.AddHours(-2),
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1),
                    CreatedAt = DateTimeOffset.UtcNow.AddHours(-3),
                    AttemptCount = 1
                },
                
                // 未使用但已过期的验证码
                new SmsVerificationCode
                {
                    PhoneNumber = "+8613800000003",
                    Code = "654321",
                    Type = SmsCodeTypes.Login,
                    IsUsed = false,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-5),
                    CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
                    AttemptCount = 0
                },
                
                // 有效的验证码（可用于测试）
                new SmsVerificationCode
                {
                    PhoneNumber = "+8613800000002",
                    Code = "888888",
                    Type = SmsCodeTypes.Login,
                    IsUsed = false,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                    CreatedAt = DateTimeOffset.UtcNow,
                    AttemptCount = 0
                },
                
                // 绑定手机号的验证码
                new SmsVerificationCode
                {
                    PhoneNumber = "+8613800000004",
                    Code = "999999",
                    Type = SmsCodeTypes.Bind,
                    IsUsed = false,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
                    CreatedAt = DateTimeOffset.UtcNow,
                    AttemptCount = 0
                },
                
                // 重置密码的验证码
                new SmsVerificationCode
                {
                    PhoneNumber = "+8613800000005",
                    Code = "111111",
                    Type = SmsCodeTypes.ResetPassword,
                    IsUsed = false,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
                    CreatedAt = DateTimeOffset.UtcNow,
                    AttemptCount = 0
                }
            };

            await context.SmsVerificationCodes.AddRangeAsync(codes);
            await context.SaveChangesAsync();

            logger.LogInformation("短信验证码数据初始化完成，共添加 {Count} 条验证码", codes.Count);
        } 

        #endregion

        #region 辅助方法

        /// <summary>
        /// 生成唯一ID（使用时间戳 + 随机数）
        /// </summary>
        private static string GenerateSubId()
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var random = RandomNumberGenerator.GetInt32(100000, 999999);
            return $"user_{timestamp}_{random}";
        }

        /// <summary>
        /// 密码哈希（使用 PBKDF2，实际生产环境建议使用 BCrypt）
        /// </summary>
        private static string HashPassword(string password)
        {
            // 注意：这是简化版本，生产环境建议使用 BCrypt
            // 安装包: Install-Package BCrypt.Net-Next
            // return BCrypt.Net.BCrypt.HashPassword(password);

            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashedBytes);
        }

        /// <summary>
        /// 生成随机IP地址
        /// </summary>
        private static string GenerateRandomIp(Random random)
        {
            return $"{random.Next(1, 255)}.{random.Next(0, 255)}.{random.Next(0, 255)}.{random.Next(1, 255)}";
        }

        /// <summary>
        /// 生成随机UserAgent
        /// </summary>
        private static string GenerateRandomUserAgent(Random random, string deviceType)
        {
            return deviceType switch
            {
                DeviceTypes.Web => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                DeviceTypes.IOS => "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
                DeviceTypes.Android => "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 Chrome/120.0.0.0",
                DeviceTypes.WeChat => "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) MicroMessenger/8.0.0",
                _ => "Mozilla/5.0 (Unknown) AppleWebKit/537.36"
            };
        }

        #endregion
    }
}
