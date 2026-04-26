using Jwt_Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Jwt_Auth.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
