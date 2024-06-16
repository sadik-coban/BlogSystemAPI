using Core.Data;
using Core.Identity;
using Core.Security;
using Entity.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public ApplicationDbContext(DbContextOptions options, IHttpContextAccessor httpContextAccessor)
    : base(options)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    public DbSet<Post> Posts { get; set; }
    public DbSet<Author> Authors { get; set; }
    public DbSet<Category> Categories { get; set; }
    public DbSet<Tag> Tags { get; set; }
    public DbSet<Administrator> Administrators { get; set; }
    public DbSet<Reader> Readers { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }



    public override int SaveChanges()
    {
        ChangeTracker.DetectChanges();
        var modified = ChangeTracker.Entries().Where(x => x.State == EntityState.Added || x.State == EntityState.Modified || x.State == EntityState.Deleted);
        var updatingUser = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.Name)!.Value;

        foreach (var item in modified)
        {
            if (item.Entity is IAuditable entity)
            {
                item.CurrentValues[nameof(IAuditable.UpdatedBy)] = updatingUser;
                item.CurrentValues[nameof(IAuditable.LastModified)] = DateTime.UtcNow;
            }
        }

        return base.SaveChanges();
    }
}
