using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class SmsVerificationCodeConfiguration : IEntityTypeConfiguration<SmsVerificationCode>
    {
        public void Configure(EntityTypeBuilder<SmsVerificationCode> builder)
        {
            builder.ToTable("SmsVerificationCodes");

            builder.HasKey(e => e.Id);
            builder.Property(e => e.Id)
                .HasDefaultValueSql("gen_random_uuid()");

            builder.HasIndex(e => e.PhoneNumber);
            builder.HasIndex(e => e.ExpiresAt);
            builder.HasIndex(e => new { e.PhoneNumber, e.Type, e.IsUsed });
            builder.HasIndex(e => e.CreatedAt);
            builder.HasIndex(e => new { e.PhoneNumber, e.Code, e.Type, e.IsUsed, e.ExpiresAt })
                .HasDatabaseName("IX_SmsCode_Lookup");

            builder.Property(e => e.PhoneNumber).HasMaxLength(32).IsRequired();
            builder.Property(e => e.Code).HasMaxLength(10).IsRequired();
            builder.Property(e => e.Type).HasMaxLength(20).IsRequired().HasDefaultValue("login");
        }
    }
}
