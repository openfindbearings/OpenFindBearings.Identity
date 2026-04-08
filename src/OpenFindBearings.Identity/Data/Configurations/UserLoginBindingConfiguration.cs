using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class UserLoginBindingConfiguration : IEntityTypeConfiguration<UserLoginBinding>
    {
        public void Configure(EntityTypeBuilder<UserLoginBinding> builder)
        {
            builder.ToTable("UserLoginBindings");

            builder.HasKey(e => e.Id);
            builder.Property(e => e.Id)
                .HasDefaultValueSql("gen_random_uuid()");

            builder.HasIndex(e => new { e.Provider, e.ProviderUserId })
                .IsUnique()
                .HasFilter("\"IsUnbound\" = false");

            builder.HasIndex(e => e.UserId);
            builder.HasIndex(e => e.UnionId);
            builder.HasIndex(e => e.BindTime);

            builder.Property(e => e.UserId).HasMaxLength(255).IsRequired();
            builder.Property(e => e.ProviderUserId).HasMaxLength(255).IsRequired();
            builder.Property(e => e.UnionId).HasMaxLength(255);
            builder.Property(e => e.ProviderNickname).HasMaxLength(100);
            builder.Property(e => e.ProviderAvatarUrl).HasMaxLength(500);
            builder.Property(e => e.RawData).HasColumnType("jsonb");

            builder.Property(e => e.Provider)
                .HasConversion<int>();
        }
    }
}
