using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using VenueBooking.Modules.Identity;
using VenueBooking.Modules.Identity.Persistence;

namespace VenueBooking.IntegrationTests.Identity;

/// <summary>
/// Boots the real API pipeline (controllers, model validation, DI wiring) against an isolated
/// in-memory database, so tests don't depend on LocalDB/Docker SQL being available.
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // AddDbContext resolves its options per-scope by default, so the database name must be
        // fixed outside the delegate — otherwise every request/scope would get a fresh Guid and
        // an isolated, empty database.
        var databaseName = $"IntegrationTests-{Guid.NewGuid()}";

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<IdentityDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<IdentityDbContext>>();

            services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase(databaseName));
        });
    }

    /// <summary>
    /// Explicit, test-owned arrange step (rather than relying on Program.cs's own startup
    /// seeding, whose timing relative to the test host isn't guaranteed) — idempotent, so it's
    /// safe to call once per test class.
    /// </summary>
    public Task SeedRolesAsync() => Services.SeedIdentityRolesAsync();
}
