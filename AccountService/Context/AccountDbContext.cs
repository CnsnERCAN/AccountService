using AccountService.Model.Entities;
using Microsoft.EntityFrameworkCore;

namespace AccountService.Context
{
    public class AccountDbContext : DbContext
    {
        public AccountDbContext(DbContextOptions<AccountDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
