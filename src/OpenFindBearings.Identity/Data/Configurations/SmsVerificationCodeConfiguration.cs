using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Data.Entities;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class SmsVerificationCodeConfiguration : IEntityTypeConfiguration<SmsVerificationCode>
    {
        public void Configure(EntityTypeBuilder<SmsVerificationCode> builder)
        {
            builder.ToTable("SmsVerificationCodes");

            builder.HasKey(e => e.Id);
            builder.Property(e => e.Id).UseIdentityColumn();

            // 索引配置
            builder.HasIndex(e => e.PhoneNumber);
            builder.HasIndex(e => e.ExpiresAt);
            builder.HasIndex(e => new { e.PhoneNumber, e.Type, e.IsUsed });
            builder.HasIndex(e => e.CreatedAt);

            // 复合索引：用于快速查找有效验证码
            builder.HasIndex(e => new { e.PhoneNumber, e.Code, e.Type, e.IsUsed, e.ExpiresAt })
                .HasDatabaseName("IX_SmsCode_Lookup");

            // 属性配置
            builder.Property(e => e.PhoneNumber).HasMaxLength(32).IsRequired();
            builder.Property(e => e.Code).HasMaxLength(10).IsRequired();
            builder.Property(e => e.Type).HasMaxLength(20).IsRequired().HasDefaultValue("login");

            // 自动清理过期验证码（需要配合 Quartz 或 Hangfire 定时任务）
            // entity.HasQueryFilter(e => e.ExpiresAt > DateTimeOffset.UtcNow && !e.IsUsed);
        }
    }
}
