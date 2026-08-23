using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Models.Entities;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenFindBearings.Identity.Data
{
    public class ApplicationDbContext : IdentityDbContext<OidcUser, IdentityRole<Guid>, Guid>
    {
        public DbSet<AuditLog> AuditLogs { get; set; } = default!;
        public DbSet<SmsCode> SmsCodes { get; set; } = default!;
        public DbSet<SystemConfig> SystemConfigs { get; set; } = default!;
        public DbSet<Tenant> Tenants { get; set; } = default!;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Identity 表重命名 + 租户影子属性
            builder.Entity<OidcUser>(e => e.ToTable("Users"));
            builder.Entity<IdentityRole<Guid>>(e =>
            {
                e.ToTable("Roles");
                e.Property<Guid?>("TenantId");
                e.HasIndex("TenantId");
            });
            builder.Entity<IdentityUserRole<Guid>>(e => e.ToTable("UserRoles"));
            builder.Entity<IdentityUserClaim<Guid>>(e => e.ToTable("UserClaims"));
            builder.Entity<IdentityUserLogin<Guid>>(e => e.ToTable("UserLogins"));
            builder.Entity<IdentityUserToken<Guid>>(e => e.ToTable("UserTokens"));
            builder.Entity<IdentityRoleClaim<Guid>>(e => e.ToTable("RoleClaims"));

            // Address 值对象配置
            builder.Entity<OidcUser>(e =>
            {
                e.OwnsOne(x => x.Address, address =>
                {
                    address.Property(a => a.Formatted).HasMaxLength(500).IsRequired();
                    address.Property(a => a.StreetAddress).HasMaxLength(500);
                    address.Property(a => a.Locality).HasMaxLength(200);
                    address.Property(a => a.Region).HasMaxLength(200);
                    address.Property(a => a.PostalCode).HasMaxLength(20);
                    address.Property(a => a.Country).HasMaxLength(100);
                });
            });

            // OpenIddict Guid 键基类实体（ReplaceDefaultEntities<Guid>() 使用）
            // TenantId 作为影子属性用于租户隔离
            builder.Entity<OpenIddictEntityFrameworkCoreApplication<Guid>>(e =>
            {
                e.ToTable("OidcApplications");
                e.Property<Guid?>("TenantId");
                e.HasIndex("TenantId");
            });
            builder.Entity<OpenIddictEntityFrameworkCoreAuthorization<Guid>>(e =>
            {
                e.ToTable("OidcAuthorizations");
                e.Property<Guid?>("TenantId");
                e.HasIndex("TenantId");
            });
            builder.Entity<OpenIddictEntityFrameworkCoreScope<Guid>>(e =>
            {
                e.ToTable("OidcScopes");
                e.Property<Guid?>("TenantId");
                e.HasIndex("TenantId");
            });
            builder.Entity<OpenIddictEntityFrameworkCoreToken<Guid>>(e =>
            {
                e.ToTable("OidcTokens");
                e.Property<Guid?>("TenantId");
                e.HasIndex("TenantId");
            });

            // 审计日志索引
            builder.Entity<AuditLog>(e =>
            {
                e.HasIndex(x => x.UserId);
                e.HasIndex(x => x.Action);
                e.HasIndex(x => x.CreatedAt);
                e.Property(x => x.Action).HasMaxLength(100);
                e.Property(x => x.ResourceType).HasMaxLength(50);
                e.Property(x => x.Status).HasMaxLength(20);
                e.Property(x => x.IpAddress).HasMaxLength(45);
                e.Property(x => x.HttpMethod).HasMaxLength(10);
                e.Property(x => x.RequestPath).HasMaxLength(500);
                e.Property(x => x.StatusCode);
                e.Property(x => x.DurationMs);
            });

            // 短信验证码索引
            builder.Entity<SmsCode>(e =>
            {
                e.HasIndex(x => x.PhoneNumber);
                e.Property(x => x.PhoneNumber).IsRequired().HasMaxLength(20);
                e.Property(x => x.Code).IsRequired().HasMaxLength(10);
                e.Property(x => x.Type).HasMaxLength(50);
            });

            // 系统配置表
            builder.Entity<SystemConfig>(e =>
            {
                e.ToTable("SystemConfigs");
                e.HasIndex(x => x.Key).IsUnique();
                e.Property(x => x.Key).IsRequired().HasMaxLength(200);
                e.Property(x => x.Value).HasColumnType("text");
                e.Property(x => x.Description).HasMaxLength(500);
            });

            // 租户表
            builder.Entity<Tenant>(e =>
            {
                e.ToTable("Tenants");
                e.HasKey(x => x.Id);
                e.HasIndex(x => x.Name).IsUnique().HasDatabaseName("IX_Tenants_Name");
                e.Property(x => x.Name).IsRequired().HasMaxLength(200);
                e.Property(x => x.Description).HasMaxLength(500);
            });

            // 用户表 - 租户关联 + 用户名+租户复合唯一索引
            builder.Entity<OidcUser>(e =>
            {
                e.HasIndex(u => u.NormalizedUserName).IsUnique(false);
                e.HasIndex(u => new { u.NormalizedUserName, u.TenantId })
                    .IsUnique()
                    .HasDatabaseName("UserNameTenantIndex");
                e.HasIndex(x => x.TenantId);
                e.Property(x => x.TenantId);
            });
        }
    }
}
