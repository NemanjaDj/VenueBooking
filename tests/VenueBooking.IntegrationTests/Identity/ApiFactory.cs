using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
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

        // Supplied explicitly rather than relying on appsettings.Development.json — tests
        // shouldn't depend on which environment/config file the test host happens to load, and
        // JwtOptions.ValidateOnStart() would otherwise fail host startup if it's missing.
        // Redirects the rolling-file sink out of the repository and gives each factory its own
        // file, so concurrently hosted test classes don't contend for one handle. The index
        // tracks the "File" entry in the API's appsettings.json "Serilog:WriteTo" array.
        var logFilePath = Path.Combine(
            Path.GetTempPath(),
            "VenueBooking.IntegrationTests",
            $"{Guid.NewGuid():N}-.jsonl");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "VenueBooking.IntegrationTests",
                ["Jwt:Audience"] = "VenueBooking.IntegrationTests",
                ["Jwt:SigningKey"] = "integration-tests-signing-key-at-least-32-bytes-long!!",
                ["Jwt:AccessTokenMinutes"] = "15",
                ["Jwt:RefreshTokenDays"] = "7",
                ["Serilog:WriteTo:1:Args:path"] = logFilePath,
            });
        });

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
