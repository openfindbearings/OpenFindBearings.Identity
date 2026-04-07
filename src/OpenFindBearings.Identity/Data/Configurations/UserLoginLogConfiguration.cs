using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Data.Entities;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class UserLoginLogConfiguration : IEntityTypeConfiguration<UserLoginLog>
    {
        public void Configure(EntityTypeBuilder<UserLoginLog> builder)
        {
            builder.ToTable("UserLoginLogs");

            builder.HasKey(e => e.Id);
            builder.Property(e => e.Id).UseIdentityColumn();

            // 索引配置（提高查询性能）
            builder.HasIndex(e => e.UserId);
            builder.HasIndex(e => e.CreatedAt);
            builder.HasIndex(e => new { e.LoginType, e.CreatedAt });
            builder.HasIndex(e => new { e.UserId, e.CreatedAt });
            builder.HasIndex(e => e.IpAddress);
            builder.HasIndex(e => e.DeviceId);

            // 复合索引：常用统计查询
            builder.HasIndex(e => new { e.LoginType, e.Status, e.CreatedAt });

            // 属性配置
            builder.Property(e => e.UserId).HasMaxLength(255).IsRequired();
            builder.Property(e => e.LoginType).HasMaxLength(30).IsRequired();
            builder.Property(e => e.Status).HasMaxLength(20).IsRequired().HasDefaultValue("success");
            builder.Property(e => e.FailureReason).HasMaxLength(500);
            builder.Property(e => e.ClientId).HasMaxLength(100);
            builder.Property(e => e.IpAddress).HasMaxLength(45);
            builder.Property(e => e.UserAgent).HasMaxLength(500);
            builder.Property(e => e.DeviceType).HasMaxLength(20);
            builder.Property(e => e.DeviceId).HasMaxLength(255);
        }
    }
}
