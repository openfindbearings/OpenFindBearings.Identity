using Microsoft.EntityFrameworkCore;

namespace OpenFindBearings.Identity.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options)
            : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder) { }
    }

}
