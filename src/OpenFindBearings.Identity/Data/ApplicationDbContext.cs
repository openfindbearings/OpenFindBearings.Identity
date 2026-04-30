using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data
{
    public class ApplicationDbContext : IdentityDbContext<OidcUser, IdentityRole<Guid>, Guid>
    {
        public DbSet<AuditLog> AuditLogs { get; set; } = default!;
        public DbSet<SmsCode> SmsCodes { get; set; } = default!;
        public DbSet<SystemConfig> SystemConfigs { get; set; } = default!;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Identity 表重命名
            builder.Entity<OidcUser>(e => e.ToTable("Users"));
            builder.Entity<IdentityRole<Guid>>(e => e.ToTable("Roles"));
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
                    address.Property(a => a.Formatted).HasMaxLength(500);
                    address.Property(a => a.StreetAddress).HasMaxLength(500);
                    address.Property(a => a.Locality).HasMaxLength(200);
                    address.Property(a => a.Region).HasMaxLength(200);
                    address.Property(a => a.PostalCode).HasMaxLength(20);
                    address.Property(a => a.Country).HasMaxLength(100);
                });
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
        }
    }
}
