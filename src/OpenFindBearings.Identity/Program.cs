using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Extensions;

var builder = WebApplication.CreateBuilder(args);

// 配置 Forwarded Headers 选项
builder.Services.ConfigureForwardedHeaders(builder.Environment.IsDevelopment());

// MVC
builder.Services.AddControllersWithViews();

// Identity
builder.Services.AddIdentityService();

// 配置 Cookie 认证
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.SlidingExpiration = true;

    // 关键：Cookie 安全设置
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;  // 始终使用 Secure（仅 HTTPS）

    // 使用统一域名
    options.Cookie.Domain = null;  // 自动使用当前域名
});

// OpenIddict
builder.Services.AddOpenIddictService(builder.Configuration, builder.Environment.IsDevelopment());

// 添加服务
builder.Services.AddApplicationServices();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// 添加CORS
builder.Services.AddCorsService(builder.Configuration);

// 添加健康检查
builder.Services.AddHealthChecksService();

var app = builder.Build();

app.Logger.LogInformation("启动 OpenFindBearings Identity");

// 1. 处理代理头，启用转发头中间件
app.UseForwardedHeaders();

// 2. 配置错误页面及其他开发环境专有设置
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();    // HSTS（可选）           
}

// 3. HTTPS 重定向
app.UseHttpsRedirection();

// 4. 路由
app.UseRouting();

// 5. CORS
app.UseCors("AllowSpecificOrigins");

// 6. 认证
app.UseAuthentication();
// 7. 授权
app.UseAuthorization();

// 8. 静态文件
app.MapStaticAssets();

// 9. 端点映射
app.MapControllers();
app.MapControllerRoute(name: "areas", pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}").WithStaticAssets();
app.MapDefaultControllerRoute().WithStaticAssets();

// 10. 健康检查
app.MapAllHealthChecks();

// 11. 执行数据库初始化
using var scope = app.Services.CreateScope();
await SeedData.SeedAsync(scope.ServiceProvider, app.Logger, app.Environment.IsDevelopment());

// 12. 启动
app.Run();
