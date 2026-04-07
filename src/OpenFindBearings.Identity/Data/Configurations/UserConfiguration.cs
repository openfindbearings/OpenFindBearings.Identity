using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenFindBearings.Identity.Data.Entities;
using System.Text.Json;

namespace OpenFindBearings.Identity.Data.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            // 表名
            builder.ToTable("Users");

            // 主键配置
            builder.HasKey(e => e.Sub);
            builder.Property(e => e.Sub)
                .HasMaxLength(255)
                .IsRequired();

            // ========== 索引配置 ==========

            // 用户名唯一索引
            builder.HasIndex(e => e.Username)
                .IsUnique()
                .HasFilter("\"Username\" IS NOT NULL");

            // 邮箱唯一索引
            builder.HasIndex(e => e.Email)
                .IsUnique()
                .HasFilter("\"Email\" IS NOT NULL");

            // 手机号唯一索引
            builder.HasIndex(e => e.PhoneNumber)
                .IsUnique()
                .HasFilter("\"PhoneNumber\" IS NOT NULL");

            // 复合索引：常用查询组合
            builder.HasIndex(e => new { e.IsEnabled, e.CreatedAt });
            builder.HasIndex(e => e.LastLoginAt);

            // ========== 属性配置 ==========

            // OIDC 核心字段
            builder.Property(e => e.Issuer).HasMaxLength(500);

            // 本地认证凭证
            builder.Property(e => e.Username).HasMaxLength(100);
            builder.Property(e => e.PasswordHash).HasMaxLength(500);
            builder.Property(e => e.Email).HasMaxLength(255);
            builder.Property(e => e.PhoneNumber).HasMaxLength(32);

            // OIDC 基本信息
            builder.Property(e => e.Name).HasMaxLength(255);
            builder.Property(e => e.GivenName).HasMaxLength(100);
            builder.Property(e => e.FamilyName).HasMaxLength(100);
            builder.Property(e => e.MiddleName).HasMaxLength(100);
            builder.Property(e => e.Nickname).HasMaxLength(100);
            builder.Property(e => e.PreferredUsername).HasMaxLength(100);
            builder.Property(e => e.ProfileUrl).HasMaxLength(500);
            builder.Property(e => e.PictureUrl).HasMaxLength(500);
            builder.Property(e => e.WebsiteUrl).HasMaxLength(500);

            // OIDC 其他信息
            builder.Property(e => e.Gender).HasMaxLength(20);
            builder.Property(e => e.Birthdate).HasMaxLength(10);
            builder.Property(e => e.Locale).HasMaxLength(20);
            builder.Property(e => e.ZoneInfo).HasMaxLength(50);

            // 业务字段
            builder.Property(e => e.LastLoginIp).HasMaxLength(45);
            builder.Property(e => e.LastLoginDevice).HasMaxLength(20);

            // ========== 地址配置（JSONB 列） ==========
            // Address 作为值对象，存储为 JSONB 格式
            // 使用 OwnsOne + ToJson() 实现
            builder.OwnsOne(e => e.Address, ownedNavigationBuilder =>
            {
                ownedNavigationBuilder.ToJson();  // PostgreSQL JSONB 列

                // 也可以显式配置 JSON 序列化选项
                // ownedNavigationBuilder.ToJson(options =>
                // {
                //     options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                // });
            });

            // ========== 自定义声明配置（JSONB 列） ==========
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

            // 通过 Metadata 设置值比较器
            property.Metadata.SetValueComparer(new ValueComparer<Dictionary<string, object>>(
                equalsExpression: (d1, d2) => AreDictionariesEqual(d1, d2),
                hashCodeExpression: d => GetDictionaryHashCode(d),
                snapshotExpression: d => CopyDictionary(d)));

            // ========== 导航关系配置 ==========
            builder.HasMany(e => e.LoginBindings)
                .WithOne(l => l.User)
                .HasForeignKey(l => l.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasMany(e => e.LoginLogs)
                .WithOne(l => l.User)
                .HasForeignKey(l => l.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        // 比较两个字典是否相等
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

        // 生成字典的哈希码
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

        // 创建字典的快照
        private static Dictionary<string, object> CopyDictionary(Dictionary<string, object>? dict)
        {
            if (dict == null) return new Dictionary<string, object>();
            return new Dictionary<string, object>(dict);
        }
    }
}
