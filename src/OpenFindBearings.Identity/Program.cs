using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data;
using OpenFindBearings.Identity.Extensions;

var builder = WebApplication.CreateBuilder(args);

// 配置 Forwarded Headers 选项
builder.Services.ConfigureForwardedHeaders(builder.Environment.IsDevelopment());

// MVC
builder.Services.AddControllersWithViews();

// OpenIddict
builder.Services.AddOpenIddictService(builder.Configuration, builder.Environment.IsDevelopment());

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// 添加CORS
builder.Services.AddCorsService(builder.Configuration);

// 添加健康检查
builder.Services.AddHealthChecksService();

var app = builder.Build();

app.Logger.LogInformation("启动 OpenFindBearings Identity");

// 【必须】在 UseAuthentication 和 UseHttpsRedirection 之前启用转发头中间件
app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseRouting();

// CORS
app.UseCors("AllowSpecificOrigins");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

// 健康检查
app.MapAllMapHealthChecks();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
// ==========================================
// 执行数据库初始化
// ==========================================
await InitializeDatabaseAsync(app);

await app.RunAsync();

static async Task InitializeDatabaseAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();

    try
    {
        await context.Database.MigrateAsync();
        await SeedData.SeedAsync(services);

        app.Logger.LogInformation("数据库初始化成功");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "数据库初始化失败");
    }
}
