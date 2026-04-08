using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; } = default!;
        public DbSet<UserLoginBinding> UserLoginBindings { get; set; } = default!;
        public DbSet<UserLoginLog> UserLoginLogs { get; set; } = default!;
        public DbSet<SmsVerificationCode> SmsVerificationCodes { get; set; } = default!;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
        }

        private void ConfigureDateTimeOffsetConversions(ModelBuilder modelBuilder)
        {
            if (Database.ProviderName?.Contains("Sqlite") == true)
            {
                var converter = new ValueConverter<DateTimeOffset, DateTime>(
                    v => v.UtcDateTime,
                    v => new DateTimeOffset(v, TimeSpan.Zero));

                foreach (var entityType in modelBuilder.Model.GetEntityTypes())
                {
                    foreach (var property in entityType.GetProperties())
                    {
                        if (property.ClrType == typeof(DateTimeOffset) ||
                            property.ClrType == typeof(DateTimeOffset?))
                        {
                            property.SetValueConverter(converter);
                        }
                    }
                }
            }
        }
    }
}
