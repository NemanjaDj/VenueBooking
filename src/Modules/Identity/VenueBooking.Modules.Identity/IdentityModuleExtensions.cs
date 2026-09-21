using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VenueBooking.Contracts.Enums;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Logging;
using VenueBooking.Modules.Identity.Persistence;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.Modules.Identity;

public static class IdentityModuleExtensions
{
    public static IServiceCollection AddIdentityModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("Default")));

        services
            .AddIdentityCore<ApplicationUser>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 8;

                // Brute-force protection: 5 failed attempts locks the account for 15 minutes.
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<IdentityDbContext>();

        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<IJwtTokenGenerator, JwtTokenGenerator>();
        services.AddSingleton<IRefreshTokenGenerator, RefreshTokenGenerator>();
        services.AddScoped<IAuthService, AuthService>();

        return services;
    }

    /// <summary>
    /// Ensures the fixed set of <see cref="UserRole"/> roles exists. Must run before any
    /// registration request, since registration assigns a role by name. Admin *users* are still
    /// created manually — this only guarantees the Admin role itself is available to assign.
    /// </summary>
    public static async Task SeedIdentityRolesAsync(this IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(IdentityModuleExtensions));

        foreach (var role in Enum.GetNames<UserRole>())
        {
            // Roles that already exist are the normal case on every start after the first, and
            // saying so each time would be noise. Only an actual change is worth an event.
            if (await roleManager.RoleExistsAsync(role))
            {
                continue;
            }

            var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if (!result.Succeeded)
            {
                var reason = string.Join(", ", result.Errors.Select(e => e.Description));
                IdentityLog.RoleSeedingFailed(logger, role, reason);
                throw new InvalidOperationException($"Failed to seed role '{role}': {reason}");
            }

            IdentityLog.RoleSeeded(logger, role);
        }
    }
}
