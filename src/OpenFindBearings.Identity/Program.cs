using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Middleware;

var builder = WebApplication.CreateBuilder(args);

// 1. Forwarded Headers
builder.Services.ConfigureForwardedHeaders(builder.Environment.IsDevelopment());

// 2. MVC
builder.Services.AddControllersWithViews();

// 改动说明：DateTime 统一输出为 UTC ISO 8601 带 Z 后缀，确保前端时区转换正确
builder.Services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(options =>
{
    options.JsonSerializerOptions.Converters.Add(new UtcDateTimeConverter());
    options.JsonSerializerOptions.Converters.Add(new NullableUtcDateTimeConverter());
});

// 3. Identity + 其内置 Cookie 方案（与 Velusia 一致：不额外配置 cookie）
builder.Services.AddIdentityService();

// 4. OpenIddict
builder.Services.AddOpenIddictService(builder.Configuration, builder.Environment.IsDevelopment());

// 5. 应用服务
builder.Services.AddApplicationServices();
builder.Services.AddCorsService(builder.Configuration);
builder.Services.AddHealthChecksService();

var app = builder.Build();

app.Logger.LogInformation("启动 OpenFindBearings Identity");

// 6. 配置错误页面及其他开发环境专有设置
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
}

// 7. 转发头（K3s 反向代理需要）
app.UseForwardedHeaders();

// 8. HTTPS 重定向
app.UseHttpsRedirection();

// 9. 安全头
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    await next();
});

// 10. 路由
app.UseRouting();

// 11. CORS
app.UseCors("AllowSpecificOrigins");

// 12. 静态文件（在认证前，避免 CSS/JS 走认证检查）
app.MapStaticAssets();

// 13. 租户上下文（必须在认证前执行）
app.UseTenantContext();

// 14. 认证
app.UseAuthentication();

// 15. 授权
app.UseAuthorization();

// 15.1 审计日志（认证之后，读取操作人身份）
app.UseMiddleware<AuditLogMiddleware>();

// 16. 端点映射
app.MapControllers();
app.MapDefaultControllerRoute().WithStaticAssets();

// 17. 健康检查
app.MapAllHealthChecks();

// 18. 执行数据库初始化
using var scope = app.Services.CreateScope();
try
{
    await SeedData.SeedAsync(scope.ServiceProvider, app.Logger, app.Environment.IsDevelopment());
}
catch (Exception ex)
{
    app.Logger.LogError(ex, "数据库初始化失败，服务继续运行，数据库相关功能暂时不可用");
}

// 19. 启动
app.Run();
