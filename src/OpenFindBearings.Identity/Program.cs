using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Extensions;
using OpenFindBearings.Identity.Middleware;

var builder = WebApplication.CreateBuilder(args);

// 1. Forwarded Headers
builder.Services.ConfigureForwardedHeaders(builder.Environment.IsDevelopment());

// 2. MVC
builder.Services.AddControllersWithViews();

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

// 9. 路由
app.UseRouting();

// 10. CORS
app.UseCors("AllowSpecificOrigins");

// 11. 租户上下文（必须在认证前执行）
app.UseTenantContext();

// 12. 认证
app.UseAuthentication();

// 13. 授权
app.UseAuthorization();

// 14. 静态文件
app.MapStaticAssets();

// 15. 端点映射
app.MapControllers();
app.MapDefaultControllerRoute().WithStaticAssets();

// 16. 健康检查
app.MapAllHealthChecks();

// 17. 执行数据库初始化
using var scope = app.Services.CreateScope();
await SeedData.SeedAsync(scope.ServiceProvider, app.Logger, app.Environment.IsDevelopment());

// 18. 启动
app.Run();
