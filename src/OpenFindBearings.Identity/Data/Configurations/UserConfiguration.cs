using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Models.Entities;
using System.Text.Json;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.ToTable("Users");

            builder.HasKey(e => e.Id);
            builder.Property(e => e.Id)
                .HasDefaultValueSql("gen_random_uuid()");

            builder.Property(e => e.Sub)
                .HasMaxLength(255)
                .IsRequired();
            
            builder.HasIndex(e => e.Sub)
                .IsUnique();

            builder.HasIndex(e => e.Username)
                .IsUnique()
                .HasFilter("\"Username\" IS NOT NULL");

            builder.HasIndex(e => e.Email)
                .IsUnique()
                .HasFilter("\"Email\" IS NOT NULL");

            builder.HasIndex(e => e.PhoneNumber)
                .IsUnique()
                .HasFilter("\"PhoneNumber\" IS NOT NULL");

            builder.HasIndex(e => new { e.IsEnabled, e.CreatedAt });
            builder.HasIndex(e => e.LastLoginAt);

            builder.Property(e => e.Issuer).HasMaxLength(500);
            builder.Property(e => e.Username).HasMaxLength(100);
            builder.Property(e => e.PasswordHash).HasMaxLength(500);
            builder.Property(e => e.Email).HasMaxLength(255);
            builder.Property(e => e.PhoneNumber).HasMaxLength(32);
            builder.Property(e => e.Name).HasMaxLength(255);
            builder.Property(e => e.GivenName).HasMaxLength(100);
            builder.Property(e => e.FamilyName).HasMaxLength(100);
            builder.Property(e => e.Nickname).HasMaxLength(100);
            builder.Property(e => e.PreferredUsername).HasMaxLength(100);
            builder.Property(e => e.ProfileUrl).HasMaxLength(500);
            builder.Property(e => e.PictureUrl).HasMaxLength(500);
            builder.Property(e => e.WebsiteUrl).HasMaxLength(500);
            builder.Property(e => e.Gender).HasMaxLength(20);
            builder.Property(e => e.Birthdate).HasMaxLength(10);
            builder.Property(e => e.Locale).HasMaxLength(20);
            builder.Property(e => e.ZoneInfo).HasMaxLength(50);
            builder.Property(e => e.LastLoginIp).HasMaxLength(45);
            builder.Property(e => e.LastLoginDevice).HasMaxLength(20);

            builder.OwnsOne(e => e.Address, ownedNavigationBuilder =>
            {
                ownedNavigationBuilder.ToJson();
            });

            var property = builder.Property(e => e.CustomClaims)
                .HasColumnType("jsonb")
                .HasConversion(
                    v => JsonSerializer.Serialize(v, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                        WriteIndented = false
                    }),
                    v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    }) ?? new Dictionary<string, object>()
                );

            property.Metadata.SetValueComparer(new ValueComparer<Dictionary<string, object>>(
                equalsExpression: (d1, d2) => AreDictionariesEqual(d1, d2),
                hashCodeExpression: d => GetDictionaryHashCode(d),
                snapshotExpression: d => CopyDictionary(d)));
        }

        private static bool AreDictionariesEqual(Dictionary<string, object>? d1, Dictionary<string, object>? d2)
        {
            if (ReferenceEquals(d1, d2)) return true;
            if (d1 == null || d2 == null) return false;
            if (d1.Count != d2.Count) return false;

            foreach (var kvp in d1)
            {
                if (!d2.TryGetValue(kvp.Key, out var value)) return false;
                if (!Equals(kvp.Value, value)) return false;
            }
            return true;
        }

        private static int GetDictionaryHashCode(Dictionary<string, object>? dict)
        {
            if (dict == null) return 0;
            var hash = new HashCode();
            foreach (var kvp in dict.OrderBy(x => x.Key))
            {
                hash.Add(kvp.Key);
                hash.Add(kvp.Value?.GetHashCode() ?? 0);
            }
            return hash.ToHashCode();
        }

        private static Dictionary<string, object> CopyDictionary(Dictionary<string, object>? dict)
        {
            if (dict == null) return new Dictionary<string, object>();
            return new Dictionary<string, object>(dict);
        }
    }
}
