using Microsoft.EntityFrameworkCore;
using OpenFindBearings.Identity.Data.Repositories.Interfaces;
using OpenFindBearings.Identity.Models.Entities;

namespace OpenFindBearings.Identity.Data.Repositories
{
    public class UserLoginLogRepository : IUserLoginLogRepository
    {
        private readonly ApplicationDbContext _context;

        public UserLoginLogRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<UserLoginLog> AddAsync(UserLoginLog log)
        {
            _context.UserLoginLogs.Add(log);
            await _context.SaveChangesAsync();
            return log;
        }

        public async Task<List<UserLoginLog>> GetByUserIdAsync(Guid userId, int count = 10)
        {
            return await _context.UserLoginLogs
                .Where(l => l.UserId == userId)
                .OrderByDescending(l => l.CreatedAt)
                .Take(count)
                .ToListAsync();
        }
    }
}
